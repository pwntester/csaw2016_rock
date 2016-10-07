import angr
import simuvex

def main():
    p = angr.Project("rock", load_options={'auto_load_libs': True})
    #s = p.factory.entry_state(args=['./rock'], add_options=simuvex.o.unicorn, remove_options={simuvex.o.LAZY_SOLVES})
    # s = p.factory.full_init_state(args=['./rock'], add_options=simuvex.o.unicorn, remove_options={simuvex.o.LAZY_SOLVES})
    s = p.factory.full_init_state(args=['./rock'], remove_options={simuvex.o.LAZY_SOLVES})
    # s = p.factory.blank_state(addr=0x401260, remove_options={simuvex.o.LAZY_SOLVES})

    # input needs to be 30 bytes long and new line
    for i in xrange(30):
        k = s.posix.files[0].read_from(1)
        s.se.add(k>0x20)
        s.se.add(k<0x7E)
        s.se.add(k!=0xA)
    # last character is new line
    k = s.posix.files[0].read_from(1)
    s.se.add(k==0xA)

    # reset the symbolic stdin's properties and set its length
    # s.posix.files[0].seek(0)
    # s.posix.files[0].length = 31

    pg = p.factory.path_group(s)
    pg.explore(find=0x40149e, avoid=0x40186d)

    print pg

    if len(pg.errored) > 0:
        print list(pg.errored[0].trace)
        print pg.errored[0].state
        pg.errored[0].retry()

    if len(pg.found) > 0:
        found_state = pg.found[0].state
        #import ipdb; ipdb.set_trace()
        return found_state.posix.dumps(0)

if __name__ == '__main__':
    print main()
