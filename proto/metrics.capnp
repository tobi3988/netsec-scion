@0xaa64bf173a6b52d7;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct MetricsPCBExt {
    payload @0 :Data;
}
