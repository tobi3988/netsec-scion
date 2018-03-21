@0xaa64bf173a6b52d7;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct MetricsPCBExt {
    fromIsdAs @0 :Text;
    toIsdAs @1 :Text;
    avgOwd @2 :Float64;
    pktReordering @3 :Float64;
    meanNormalized @4 :Float64;
    pktLoss @5 :Float64;
    variance @6 :Float64;
    percentile999 @7 :Float64;

}
