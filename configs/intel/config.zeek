@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

redef Intel::read_files += { "/data/intel/intel.dat" };

# Suspend packet processing until the Intel framework finishes reading the feed asynchronously
event zeek_init() &priority=-10 {
    suspend_processing();
}

event Input::end_of_data(name: string, source: string) {
    if ( source == "/data/intel/intel.dat" ) {
        continue_processing();
    }
}
