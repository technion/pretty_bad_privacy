# PBP
## Pretty Bad Privacy

Theoretically this app should produce pretty good privacy. Theory however is not aligned with practice. No matter how clear I make it that this is a weekend Rust project, someone get upset about "rolling your own crypto". This app is named `PBP` specifically to make such project status clear.

Note that as this is just a block cipher implementation, the hard part of crypto (key management) isn't considered. The passphrase hash is just there to ensure whatever you supply is the right length.

## Algorithm

The implemented algorithm is mostly described here: https://soatok.blog/2022/12/21/extending-the-aes-gcm-nonce-without-nightmare-fuel/

Some of the design changes we've made are:
- Implement only 256 bit key support, we get to ignore the 128 bit  branch of the algorithm
- Modifying the hash to look like the actual HKDF algorithm makes it less "roll your own" controversial
- Implement a third derived output, a commitment key which is added to the Additional Data, used to mitigate key commitment complaints

## Prototype

There's a Ruby script in this repo that implements the workflow in a simple to read format, which serves to produce output validation.