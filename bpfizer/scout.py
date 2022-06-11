import inspect

class Scout(object):
    def __init__(self, tracer, ip, op, operands=[]):
        self.tracer = tracer
        self.operands = operands
        self.op = op
        self.ip = ip

        tracer.found_insn(self)
        pass

    def __lt__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '<', [self, other])

    def __le__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '<=', [self, other])

    def __eq__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '==', [self, other])

    def __ne__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '!=', [self, other])

    def __gt__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '>', [self, other])

    def __ge__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '>=', [self, other])

    def __bool__(self):
        ip = inspect.stack()[1].frame.f_lasti
        return self.tracer.do_bool(self, ip)

    def __add__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '+', [self, other])

    def __sub__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '-', [self, other])

    def __mul__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '*', [self, other])

    def __rmul__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '*', [other, self])

    def __floordiv__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '//', [self, other])

    def __truediv__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '/', [self, other])

    def __rtruediv__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '/', [other, self])

    def __and__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '&', [self, other])

    def __or__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '|', [self, other])

    def __xor__(self, other):
        ip = inspect.stack()[1].frame.f_lasti
        if not isinstance(other, Scout):
            other = self.tracer.get_const_scout(other)
            pass
        return Scout(self.tracer, ip, '^', [self, other])

    def __call__(self, *args, **kws):
        ip = inspect.stack()[1].frame.f_lasti
        return Scout(self.tracer, ip, 'call', [self])
    pass


class Insn(object):
    def __init__(self, ip):
        self.ip = ip
        self.opvs = set()
        self.br = [-1, -1]
        pass

class Tracer(object):
    def __init__(self):
        self.insns = {}
        self.lasti = -1
        self.op = ''
        self.conditions = []
        self.consts = {}
        pass

    def get_const_scout(self, v):
        if v in self.consts:
            return self.consts[v]

        scout = Scout(self, -1000000 - len(self.consts), 'const')
        scout.value = v
        self.consts[v] = scout
        return scout

    def found_insn(self, scout):
        ip = scout.ip
        if ip not in self.insns:
            self.insns[ip] = Insn(ip)
            insn = self.insns[ip]
            insn.op = scout.op
            pass

        insn = self.insns[ip]
        insn.op = scout.op
        assert(insn.op == scout.op)
        v = tuple([op.ip for op in scout.operands])
        insn.opvs.add(v)

        if ip >= 0 and self.lasti >= 0:
            last_insn = self.insns[self.lasti]
            if last_insn.op == '?':
                cond_idx = last_insn.cond_idx
                cond_val = self.conditions[cond_idx]
                if cond_val:
                    last_insn.br[0] = ip
                else:
                    last_insn.br[1] = ip
                    pass
            else:
                last_insn.br[0] = ip
                pass
            pass
        if ip >= 0:
            self.lasti = ip
            pass
        pass

    def do_bool(self, scout, ip):
        is_new = ip not in self.insns
        scout = Scout(self, ip, '?', [scout])
        if is_new:
            self.insns[ip].cond_idx = len(self.conditions)
            self.conditions.append(False)
            pass
        cond_idx = self.insns[ip].cond_idx
        return self.conditions[cond_idx]

    def _enum_conds(self):
        if len(self.conditions) == 0:
            return False

        saved_first = self.conditions[0]

        for cond_i in range(len(self.conditions) - 1, -1, -1):
            if not self.conditions[cond_i]:
                self.conditions[cond_i] = True
                break
            self.conditions[cond_i] = False
            pass
        return not (saved_first and not self.conditions[0])

    def trace(self, func):
        args = [Scout(self, -1 - i, 'arg', [])
                for i in range(func.__code__.co_argcount)]
        for i, arg in enumerate(args):
            self.insns[arg.ip].name = func.__code__.co_varnames[i]
            pass
        glob = {}
        for i, vname in enumerate(func.__code__.co_names):
            scout = Scout(self, -2000000 - i, 'global', [])
            self.insns[scout.ip].name = vname
            glob[vname] = scout
            pass

        func = func.__class__(func.__code__, glob, func.__name__)

        self.lasti = -1
        r = func(*args)
        rscout = Scout(self, 1000000, 'return', [r])

        while self._enum_conds():
            self.lasti = -1
            r = func(*args)
            rscout = Scout(self, 1000000, 'return', [r])
            pass
        pass

    def debug_show(self):
        ips = list(self.insns.keys())
        ips.sort()
        for i, ip in enumerate(ips):
            insn = self.insns[ip]

            if ip <= -2000000:
                print('%04d: %s %s' % (ip, insn.op, insn.name))
            elif ip <= -1000000:
                scout = self.get_const_scout(ip)
                print('%04d: %s %s' % (ip, insn.op, repr(scout.value)))
            elif ip < 0:
                print('%04d: %s %d %s' % (ip, insn.op, -ip - 1, insn.name))
            elif insn.op == '?':
                print('%04d: ? operands=%s\n\tTrue:%d False:%d' % (ip, repr(insn.opvs), insn.br[0], insn.br[1]))
            else:
                if i < len(ips) - 1:
                    next_ip = ips[i + 1]
                else:
                    next_ip = -1
                    pass
                if next_ip == insn.br[0]:
                    print('%04d: %s operands=%s' % (ip, insn.op, repr(insn.opvs)))
                else:
                    print('%04d: %s operands=%s\n\tgoto %d' % (ip, insn.op, repr(insn.opvs), insn.br[0]))
                    pass
                pass
            pass
        pass
    pass

def bar():
    pass

def test(a, b):
    c = a + b + bar() + foo
    if c > 300:
        d = c * 6 + b
    elif c < 30:
        tiger()
        d = c * 3 + b * a
    else:
        d = 2 * c * 2 + 5 / b / a
    return d + c

tracer = Tracer()
tracer.trace(test)
tracer.debug_show()
