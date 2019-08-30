#!/usr/bin/python3

'''
Create a Graphviz diagram of AS paths to reach a given prefix
'''

from argparse import ArgumentParser, RawTextHelpFormatter
import ipaddress
import os
from sys import exit
import time
import yaml
from akgRoutes import *
from jnpr.junos import Device
import pygraphviz as pgv


def setConfigOptions():
    """
    setup various options for the script
    config file is YAML
    REQUIRED: list of routers with addresses, username & private key file, start node parameters
              these are read from the config file *only*
    OPTIONAL: there are several graph options for which we have default options set.  The example config file
              has these options set to recommended default values.
              These default values can be overridden  with command line flags
              In the event that a config file doesn't contain the options AND nothing is received from argparse,
              we'll still set recommended defaults.
              To accomplish this, argparse sets the variable to Nonetype.  If it doesn't exist (meaning, no this
              parameter wasn't passed on the command line) , try to read it from the config file.
              If the key:value pair doesn't exist in the config file, create it with default vals
    :return:
    """
    parser = ArgumentParser(description="Graph AS paths to prefix", formatter_class=RawTextHelpFormatter)
    parser.add_argument('prefix', metavar='prefix', type=str)
    parser.add_argument('-c', '--config', dest='c', metavar='',
                        action="store", default='config.yml',
                        help="specify an alternate config file\n(default=config.yml)")
    parser.add_argument('-d', '--dumpdot', dest='d',
                        action="store_true", default=None,
                        help="dump graphviz data in dot format prior to layout.")
    parser.add_argument('-s', '--no-strict', dest='s',
                        action="store_false", default=None,
                        help="disable creating a strict graph\n"
                             "(default is strict (ie, max one edge between nodes))")
    parser.add_argument('-e', '--edge-color', dest='e',
                        action="store_true", default=None,
                        help="enable color coding edges by local pref\n(default is don't color code)")
    parser.add_argument('-f', '--first-hop', dest='f',
                        action="store_true", default=None,
                        help="force first hop AS nodes to be on the same level\n(may make ugly graph in some cases)")
    parser.add_argument('-l', '--last-hop', dest='l',
                        action="store_true", default=None,
                        help="force terminating AS nodes to be on the same level\n(may make ugly graph in some cases)")

    args = parser.parse_args()

    prefix = args.prefix
    configfile = args.c
    clidump = args.d
    clistrict = args.s
    cliedgecolor = args.e
    clifirsthop = args.f
    clilasthop = args.l

    try:
        with open(configfile, 'r') as f:
            config = yaml.load(f)
    except FileNotFoundError:
        exit('config file {} not found.  '
             'Either specify a config file with "-c <filename>" or create a file named config.yml\n'
             'See config-SAMPLE.yml for format and required and optional fields with defaults'.format(configfile))

    if clidump is None:                                         # option not passed as command line arg
        if 'dumpplot' not in config['graphopts'].keys():        # check the config file to see if the option exists
            config['graphopts']['dumpplot'] = False             # if it doesn't establish recommended default
    else:
        config['graphopts']['dumpplot'] = clidump               # use command line value if present
    if clistrict is None:
        if 'strict' not in config['graphopts'].keys():
            config['graphopts']['strict'] = True
    else:
        config['graphopts']['strict'] = clistrict
    if cliedgecolor is None:
        if 'edgecolor' not in config['graphopts'].keys():
            config['graphopts']['edgecolor'] = False
    else:
        config['graphopts']['edgecolor'] = cliedgecolor
    if clifirsthop is None:
        if 'firsthop' not in config['graphopts'].keys():
            config['graphopts']['firsthop'] = False
    else:
        config['graphopts']['firsthop'] = clifirsthop
    if clilasthop is None:
        if 'lasthop' not in config['graphopts'].keys():
            config['graphopts']['lasthop'] = False
    else:
        config['graphopts']['lasthop'] = clilasthop

    rtrdict = config['routers']
    username = config['credentials']['username']
    path2keyfile = config['credentials']['path2keyfile']
    return prefix, rtrdict, username, path2keyfile, config['graphopts'], config['startnode']


def validatePrefix(inprefix):
    """
    validate prefix input.  ensure it's a good IPv4 or IPv6 address and that it's global unicast
    return version so we know which table to query
    :param inprefix:
    :return: version number
    """
    # make sure it's something that looks like an address
    try:
        ipaddress.ip_address(inprefix)
    except ValueError:
        exit("{} doesn't appear to be a valid address".format(inprefix))
    if not ipaddress.ip_address(inprefix).is_global:
        exit("{} is not a global prefix.".format(inprefix))
    if ipaddress.ip_address(inprefix).is_link_local:
        exit("{} is link local.".format(inprefix))
    if ipaddress.ip_address(inprefix).is_loopback:
        exit("{} is a loopback.".format(inprefix))
    if ipaddress.ip_address(inprefix).is_multicast:
        exit("{} is a multicast prefix.  Can't graph those.".format(inprefix))
    if ipaddress.ip_address(inprefix).is_private:
        exit("{} is a private address.  Wont try.".format(inprefix))
    if ipaddress.ip_address(inprefix).is_reserved:
        exit("{} is a reserved prefix.".format(inprefix))
    return ipaddress.ip_address(inprefix).version


def extractPath(inpath):
    """
    the returned AS path from the router is in the form
        "AS path: ASN* I AS path: Recorded", for example:
        'AS path: 65513 65514 I AS path: Recorded'
    we only want the ASNs, so we have to ignore the leading "AS path:" and extract any string that contains an integer.
    Once we hit a non integer (in this example "I"), stop processing and return a list of strings representing
    the bare AS path (in this example ['65513', '65514']
    :param inpath:
    :return: list of strings
    """
    tpath = inpath.split()
    path = []
    for item in tpath:
        if not (item == 'AS' or item == 'path:'):
            if item.isdigit():
                path.append(item)
            elif item == "I":       # 'I' indicates IGP, so we can stop processing at this point
                break               # Things past 'I' can screw with the graph- especially aggregators.
    return path


def extractData(routes):
    """
    extract useful data being returned from the router.  specifically, localpref and AS path
    if there are no paths in any of the responses from the router, bail because that indicates a 'network not in table'
    or 'route not found' condition (if a route is in one router, but not others, then iBGP might be broken because
    there should be a full mush, so if one router has a path, then they should all have it)
    """
    tpathlst = []
    thisrouterspaths = {}
    for entry in routes:
        aspathtype = type(entry.aspath)
        if entry.aspath == 'AS path: I AS path: Recorded' or \
           entry.aspath == ['AS path: I AS path: Recorded', 'AS path: I AS path: Recorded']:
            exit("Route not found in at least one router....exiting")
        if isinstance(entry.aspath, str):                   # catch the instance where the router returns exactly
            for index, path in enumerate([entry.aspath]):   # one route, in which case, aspath is a str not list
                tinnerdict = {}
                tinnerdict['localpref'] = entry.lp[index]
                tinnerdict['ASPath'] = extractPath(path)
                tinnerdict['peerid'] = entry.peerid[index]
                tpathlst.append(tinnerdict)
        else:                                                 # this is the more common case
            for index, path in enumerate(entry.aspath):       # the router returns a list of strings for AS Path
                tinnerdict = {}
                tinnerdict['localpref'] = entry.lp[index]
                tinnerdict['ASPath'] = extractPath(path)
                tinnerdict['peerid'] = entry.peerid[index]
                tpathlst.append(tinnerdict)
    thisrouterspaths['pathdetails'] = tpathlst
    return thisrouterspaths


def getPaths(routers, username, path2keyfile, prefix, version):
    """
    log into each router, get route data for destination
    call extract data to build data structure
    :param routers: list of routers
    :param username: username with at least RO privs
    :param path2keyfile: ssh private key
    :param prefix: destination prefix
    :return: sourcedict (nested dictionary:
             {'routername': {'pathdetails': [ {'ASPath': [], 'localpref': '', 'peerid': ''} ] } }
    """
    sourcedict = {}
    for key, router in routers.items():
        dev = Device(router, user=username, ssh_private_key_file=path2keyfile)
        dev.open(gather_facts=False)
        r = akgRouteTable(dev)
        if version == 4:
            r.get(destination=prefix, extensive=True, table='inet.0')
        else:
            r.get(destination=prefix, extensive=True, table='inet6.0')
        dev.close()
        sourcedict[key] = extractData(r)
    return sourcedict


def createColorMap(insource, edgecolor):
    """
    attempt to color code edges based on localpref
    most preferred is green, least preferred is black, everything in between is blue
    in the event the user requests us to disable edge color coding, we'll set all dictionary values to 'black'
    we still need to generate a dictionary of {localprefs: color} even if color coding is disabled
    because preProcessPaths expects a dictionary of LP: color
    :param insource:
    :param edgecolor - bool indicating if edges should be color coded
    :return: colordict: a dictionary with integer keys for localpref and values are color names
    """
    localprefset = set()                            # use a set because it automatically deduplicates localpref values
    for router, thing in insource.items():
        for pd, value in thing.items():
            for path in value:
                localprefset.add(int(path['localpref']))
    colorlist = ['green'] * len(localprefset)
    # convert localprefs set to a list so we can use indexes
    localpreflist = list(localprefset)
    localpreflist.sort(reverse=True)
    i = 0
    while i < len(localpreflist) - 1:
        if localpreflist[i + 1] == localpreflist[i]:
            pass
        else:
            colorlist[i + 1] = 'blue'
        i += 1
    colorlist[-1] = 'black'
    colordict = dict(zip(localpreflist, colorlist))
    if edgecolor:
        return colordict
    else:
        return colordict.fromkeys(colordict, 'black')


def preProcessPaths(indata, cmap, snodelabel):
    """
    preprocess data structure to make generating the graphviz easier.
    specifically, we'll add starting node to the beginning of every AS path
    also, add a new K:V pair to the inner dictionary that maps localpref to the desired edge color
    :param indata: main data structure
    :param cmap dictionary of colormapping for edges
    :param snodelabel: start node label
    :return: modified 'sourcedict' with added keys
    """
    for router, pds in indata.items():
        for k, v in indata[router].items():
            for path in v:
                path['ASPath'].insert(0, snodelabel)
                path['edgecolor'] = cmap[int(path['localpref'])]
    return indata


def groupFirstAndLast(indata):
    """
    generate two lists: one each for the first hop ASNs and last hop ASNs
    This function is called if the user requests either first and/or last hop ASNs be forced to same level
    :param indata:
    :return: list for first hope ASNs and last hop ASNs
    """
    termAS = set()
    startAS = set()
    for router, pd in indata.items():
        for details in pd.values():
            for item in details:
                startAS.add(item['ASPath'][1])
                termAS.add(item['ASPath'][-1])
    return startAS, termAS


def makeGraph(inpaths, prefix, graphopts, startnode):
    """
    create a graphviz graph.
    :param inpaths: nested dict that has ASPaths and colors
    :param prefix: original prefix user requested (for the title)
    :param graphopts - dictionary of graph options
    :param startnode - dictionary describing start node attributes
    :return: nothing- generate a png (and dot file, if requested)
    """
    G = pgv.AGraph(strict=graphopts['strict'], directed=True)
    G.graph_attr.update(label="AS path to " + prefix + '\n\n', labelloc="t")
    for router, pds in inpaths.items():
        for k, v in inpaths[router].items():
            for path in v:
                edgelist = []
                i = 0
                while i < len(path['ASPath']) - 1:
                    edge = path['ASPath'][i],  path['ASPath'][i + 1]
                    edgelist.append(edge)
                    i += 1
                G.add_edges_from(edgelist, color=path['edgecolor'])
    G.add_node(startnode['label'],
               color=startnode['color'],
               fontcolor=startnode['fontcolor'],
               style=startnode['style'])
    if graphopts['firsthop'] or graphopts['lasthop']:
        print("first or last hop subgraph option selected, creating ASN list")
        startAS, termAS = groupFirstAndLast(inpaths)
    if graphopts['firsthop']:
        G.add_subgraph(startAS, rank='same')
    if graphopts['lasthop']:
        G.add_subgraph(termAS, rank='same')
    tfilename = './output/PathTo_' + str(prefix) + '_' + time.strftime("%d%b%Y-%H%M")
    filename = tfilename.replace(':', '-')  # convert colons in v6 addrs to dashes because colons are bad in filenames
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    if graphopts['dumpplot']:
        G.write(filename + '.dot')
        print("Graphviz file is written as {}".format(filename + '.dot'))
    G.layout(prog='dot')
    G.draw(filename + '.png')
    print("Output is {}".format(filename + '.png'))


def main():
    prefix, rtrdict, username, path2keyfile, graphopts, startnode = setConfigOptions()
    print("Got these graph options: {}".format(graphopts))
    version = validatePrefix(prefix)
    allpaths = getPaths(rtrdict, username, path2keyfile, prefix, version)
    colormapping = createColorMap(allpaths, graphopts['edgecolor'])
    finalpaths = preProcessPaths(allpaths, colormapping, startnode['label'])
    makeGraph(finalpaths, prefix, graphopts, startnode)

main()

