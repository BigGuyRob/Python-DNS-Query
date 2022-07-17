# CS352 Project 1
#
# 0.
# Team Member 1 - Kiernan King | ktk43
# Team Member 2 - Robert Reid | rlr151
#
# 1.
# No functions or functions that aren't currently working.
#
# 2.
# Both team members collaborated, and resources referenced include: 
# - The Python Socket documentation found at https://docs.python.org/3/library/socket.html for socket, timeout, and getting hostname information.
# - The Python Binascii documentation https://docs.python.org/3/library/binascii.html for converting hex to binary
# - Hand Writing DNS messages found at https://routley.io/posts/hand-writing-dns-messages/
# - DNS Server Query information found at https://datatracker.ietf.org/doc/html/rfc1035
# - Domain Name information found at https://datatracker.ietf.org/doc/html/rfc1035
# 3. 
# The problems faced in the process of developing this code are referenced in the documentation above. 
# One thing that was difficult initially was figuring out which format to encode the message. The routley post was helpful, but lacked the information on how to actually get the message into binary. We wanted to make the program as illustrative as possible to the process of encoding the DNS query which included being able to show exactly which bits went where. Another problem that was faced was figuring out a mechanism to decode both the question and the answer data. The labels that denote the # length of the data is 2 octets in the answer portion and is different to identifiable in the compressed vs uncompressed case.  
# 4.
# The level of standardization required incredible forethought and planning. Reading the RFCs showed how the infrastructure is not just made of a system of systems that 
# perform a shared task of converting domain names to IP addresses also is able to have mechanisms in place for caching, routing, recursion, and so much more 
# sophisticated synchronization mechanisms and protocols. Its hard to believe this functionality is a black box we dont really have to think about.
# 
