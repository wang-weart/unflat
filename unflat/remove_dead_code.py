from ida_hexrays import *
import ida_segment
import logging
from .logger_config import get_logger

class RemoveDeadCode(minsn_visitor_t):
    def __init__(self):
        self.minsn_line = 0
        self.mop_list = []
        self.black_mop_list = []
        super().__init__()

    def visit_minsn(self):
        minsn = self.curins
        self._optimizer(minsn)
        return 0

    def _optimizer(self, minsn:minsn_t):
        # mopOptimizer = MopOptimizer()
        # minsn.for_all_ops(mopOptimizer)
        logging.debug(f"{self.minsn_line}: {minsn.dstr()}")
        self._find_ori_minsn(minsn)
        self.minsn_line += 1

    def _find_ori_minsn(self, minsn:minsn_t):
        # print(minsn.dstr())
        if minsn.l.t == mop_d:
            self._find_ori_minsn(minsn.l.d)
        if minsn.r.t == mop_d:
            self._find_ori_minsn(minsn.r.d)
        if minsn.r.t == mop_v and minsn.r.size > -1:
            self.mop_list.append(minsn.r)
        if minsn.l.t == mop_v and minsn.l.size > -1:
            self.mop_list.append(minsn.l)
        if minsn.d.t == mop_v and minsn.l.size > -1:
            self.black_mop_list.append(minsn.d)

    def optimizer(self):
        black_mop_addr = []
        for mop in self.black_mop_list:
            black_mop_addr.append(mop.g)
        for mop in self.mop_list:
            mop_str = mop.dstr()
            seg:ida_segment.segment_t = ida_segment.getseg(mop.g)
            if mop.g not in black_mop_addr and ida_segment.get_segm_name(seg) == ".bss":
                mop.make_number(0, mop.size)
                mop_new_str = mop.dstr()
                logging.info(f"修改{mop_str} -> {mop_new_str}")