# Hermit networking adaptations

`hyper-util` is version 0.1.14 from crates.io. Its Hermit TCP connector uses the
Hermit socket2 backend and transfers a connected descriptor into Tokio. The
pinned kernel reports connect errors synchronously and does not implement
SO_ERROR. A Tokio blocking task performs connect, then from_std registers the
successful stream. Socket options are set before platform conversion. The unused
HTTP2 timer is explicitly consumed when HTTP2 is disabled.

`socket2` comes from hermit-os/socket2 commit
2bb3d15b3cf7b3ec7a89852e1605f4a987e00d03 (0.5.9). Its behavior modification is
returning unrecognized negative Hermit errors as io::Error instead of panicking.
An allowance also suppresses pre-existing nested-unsafe macro warnings.
This preserves the OS error code for failures such as EFAULT on interrupted
connections.

Upstream license files accompany both copies. These are pinned compatibility
patches, not automatic updates to upstream dependencies.
