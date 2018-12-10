from optparse import OptionParser


class Options:

    def __init__(self):

        self.parser = OptionParser()

    def get_options(self):

        self.parser.add_option("-t", "--target", dest="target", type=str, default=None,
                               help="Sets the target ip for the vulnerability scan")

        self.parser.add_option("-r", "--range", dest="range", type=str, default=None,
                               help="Sets the range to use for the network scan aka 10.10.0.1/24")

        self.parser.add_option("", "--threads", dest="threads", type=int, default=300,
                               help="Sets the limit for the maximum number of threads that can be using when scanning "
                                    "ip range for open ports. Default is 300 threads")

        self.parser.add_option("", "--request_timeout", dest="request_timeout", type=int, default=3,
                               help="Sets the timeout for requests when scanning ip range for open ports. "
                                    "Default is 3 seconds")

        self.parser.add_option("", "--place_holder", dest="place_holder", default=False, action="store_true",
                               help="")

        return self.parser.parse_args()[0]
