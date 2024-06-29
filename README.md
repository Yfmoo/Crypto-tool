# Crypto-tool
Fernet算法解释

想象一下，你有一封信，你想要安全地寄给一个朋友，但是你担心信件在传递的过程中被别人偷看或者修改。为了确保信件的内容保密且没有被篡改，你可以使用Fernet算法来帮忙。

首先，你和你的朋友需要事先约定一个“密码”。这个密码只有你们两个人知道，而且要保密。这个密码就像是一把钥匙，既能用来锁箱子，也能用来解锁箱子。

当你想要寄信时，你先把信放进一个特殊的箱子里，这个箱子有锁（就像保险柜一样）。然后，你用你们事先约定的密码来锁上这个箱子。这样，即使信件在传递过程中被别人拿到，没有密码他们也无法打开箱子看到信的内容。

但是，仅仅锁上箱子还不够安全，因为你还需要确保信在箱子里没有被偷偷换掉。为了做到这一点，你在锁上箱子之前，还做了一件事情：你把信的内容复制了一份，用一种特殊的方式（就像把复印件放进碎纸机一样）处理了一下，得到了一个“信的指纹”。然后，你把这个“指纹”贴在了箱子的外面。

当你的朋友收到箱子后，他首先检查“指纹”，确保信在箱子里没有被换掉。如果“指纹”对得上，说明信是安全的。接下来，他用你们约定的密码来解锁箱子，这样就能看到信的内容了。

Fernet算法就像是这个过程中的锁、箱子和“指纹”。它使用一种叫做AES的加密方法来锁箱子（加密信件），用HMAC来制作“指纹”（确保信件完整性），还加入了时间戳，这样如果信件过了很久才到达，你的朋友就知道这封信可能已经不新鲜了，可能不再想要打开了。

总之，Fernet算法是一种安全地发送秘密消息的方法，它能保证消息在传递的过程中既保密又完整，就像是用密码锁的保险柜来寄信一样。


使用事项
--文件加解密导出的文件默认在当前代码目录下

--古典密码中ADFGVX...-Four与Beafort-vernam暂时无用

--Caser的key为偏移量

--Veginere的key为偏移量

--Atbash无key，输入不影响加解密结果

--Playfair默认偏移量为2，可在key中修改

--Mose默认以“/”代替空格

--Base家族中62，91-100无算法

