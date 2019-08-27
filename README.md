# Graph AS path by Prefix

This script will graph the AS path taken to a given prefix.

It uses [PyGraphviz](https://pygraphviz.github.io/) to build and create the graph.

Output is a png to ./output/

The script requires a configuration file in YML for a number of required and options parameters.  This repo contains a
sample file.  The format is documented below.

### Usage
```
usage: PrefixGraph.py [-h] [-c] [-d] [-s] [-e] [-f] [-l] prefix

Graph AS paths to prefix

positional arguments:
  prefix

optional arguments:
  -h, --help        show this help message and exit
  -c , --config     specify an alternate config file
                    (default=config.yml)
  -d, --dumpdot     dump graphviz data in dot format prior to layout.
  -s, --no-strict   disable creating a strict graph
                    (default is strict (ie, max one edge between nodes))
  -e, --edge-color  enable color coding edges by local pref
                    (default is don't color code)
  -f, --first-hop   force first hop AS nodes to be on the same level
                    (may make ugly graph in some cases)
  -l, --last-hop    force terminating AS nodes to be on the same level
                    (may make ugly graph in some cases)

```

**-d, --dumpdot** - in addition to producing an image, also save the graph in `dot` file format.
This might be useful for use in other programs that understand Graphviz.

**-s, --no-strict** - by default, the program will generate a 'strict' graph, meaning, there is at most one edge per
node.  This generally makes the graphs easier to read

**-e, --edge-color** - enable edge color coding.  By default, the script will not color code edges by localpreference.  See
below for more detail

**-f, --first-hop** - force all the first hop AS nodes to be on the same level. This makes the relationship of first hop
networks (such as transit providers and peers) a little clearer, however, in the case where the terminating AS is also a first hop, or in cases where first hop nodes have connections between themselves, the graph can be more confusing

**-l, --last-hop** - In the event multiple autonomous systems advertise the same prefix (split origin), this option (similar to **-f**) will force all the terminating nodes to be on the same level
As with **-f** this can make ugly graphs in some cases.

### Configuration
The script requires a YML configuration file that contains a number of required and optional parameters.
The required parameters are:

`routers` - a list of routers to query.

`credentials` - the username and location of ssh private key file.

`startnode` - parameters for the starting node.  Customize with your AS name and org colors if you like.

`graphopts` - a number of options used to configure Graphviz.  These are default values that can be modified at runtime with command line flags as described above or with `--help`

  * `dumpplot` - in addition to generating a graph, also dump the raw `dot` file.  This can be useful if you want to work with the graph in an applicaiton that understands [Graphviz](https://www.graphviz.org/) `dot` format

  * `strict` - Create a strict graph with only one edge (or line) between nodes.  This makes the graph easier to read, but as the paths converge towards the terminating AS, the specific path used becomes unclear.

  * `edgecolor` - Enable color coding of edges by local preference.  Green is most preferred, black is least preferred, and everything in between is blue.  This is disabled by default because it can sometimes be misleading, especially if there are multiple connections between AS nodes.

  * `firsthop` - Force all first hop AS nodes to be on the same level. Disabled by default because this can sometimes make graphs ugly and hard to read, especially if: the terminating node is also a first hop node; if the first hop (or latter) nodes have connections to other first hops.

  * `lasthop` - Similar to `firsthop`, this forces all terminating nodes to be at the same level.  This is only useful when the prefix is announced by multiple autonomous systems.



#### Note on color coding of edges
The script can try to show which paths are preferred by using LOCALPREF as a key to color coding.
Most preferred paths are green, least preferred are black, everything in between is blue.

While this is useful, it can also be misleading.  Hot potato routing, multiple sessions between the same AS, and other reasons can confuse the color coding scheme.  Also, with a strict graph (which is the default), as the paths converge close to the destination becomes, the color coding becomes ambiguous.


#### Prepending
If at any point along the path, an AS uses prepending (ie, we see repeats of the same ASN), Graphviz will represent this as "self-loops" or "self-edges."  That is, a node will have an edge to itself.
