==============
BPF Analysis
==============

First Impressions
==================

My experience with bpf, for now, has been unpleasant. My attempt of writing an ssl parser which extracts the service name indication
from inside an ssl packet has been rather frustrating. Unfortunately, because of the limitations imposed by the bpf verifier, it
was quite hard to parse a packet with variable length. To parse the client hello message, it is necessary to loop through the ssl
extensions inside the packet until you find the one corresponding to the service name indication. As it is known, at least for now,
the bpf verifier doesn't allow any programs with loops or recursion to be loaded into the kernel which makes it quite hard to write
such a program. Even though the bpf verifier doesn't allow loops, it was possible to use a "trick" that would make it possible to write
a for loop, however that loop needed to be bounded, which led to the creation of "artificial boundaries". For example, it was necessary
to limit the total amount of extensions we could parse inside the packet, we chose to bound them to 53, because it is the current amount
of ssl extensions available. Other artificial boundaries created were relative to the size of the offsets. For example, when we added a
variable sized offset to the packet, sometimes, the verifier would not update the packet's offset and, therefore, would not allow us to
access content from that offset onwards. This forced us to bound the variable sized offsets, so that the verifier would update the packet's
offset in this case, and, consequently, grant us access to the rest of it's content.
