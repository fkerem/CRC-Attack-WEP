# CRC-Attack-WEP

WEP uses encrypted CRC-32 as the integrity protection mechanism.
However, there is a flaw in the mechanism due to the linearity of CRC-32 so that the attacker can selectively flip some bits of the message.

The attack is illustrated by flipping 4th, 6th, 10th, 20th, 24th and 36th bits of the message in this repository.
Run simulate.py for the illustration.
