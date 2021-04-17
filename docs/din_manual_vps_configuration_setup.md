# DIN Manual VPS Configuration Setup : For SINOVATE Mainnet

**An Ubuntu 18.04 VPS with 1 Cpu and  1GB MB Ram is needed.**
  
<br>
Download putty or any SSH client program of your choice [https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html.)

<br>
  

> **Enter your IP information for the new VPS and click on the `` Open `` Button.**

<br>
<br>

![](https://lh3.googleusercontent.com/IE_vYDIEvnK6jfShZ7Vunke7cxwzPyBQDZebD3WF7B8D367gycEusFnxiVBRF91eFpib-LFhx8tsg2BQjP3sUBBg2bz40RjGxIRBRnusRtN3XawkCNa-GQpEa8oONEalFvM3Qumn)

<br>
  

> Enter your username as ``root`` and enter the password given to you.  
Some VPS providers may ask you to change your temporary password immediately.

<br>

![](https://lh4.googleusercontent.com/vlShobe_0C-5xj1pQnyvnGPOd4D67X2DlQRvjtxE7ful4BnpphBosNdSDWRIkA1fn3HAGRfKbGLS2DJRKxMtUJQOsNt2vHR3ik3uVdhxpALsyRGIGTEnn4ViKSns8rIx5MsuemvU)

  <br>
  
  

![](https://lh5.googleusercontent.com/JfPUiLtMpliPotEHTCjxP9qnxyj5-TszcLSqBEapuwRWLoMiE1RCth19b8a5pBVI2nrQNrXJFfasZUAY5P_hynlj-PxD8im_kLRIQTLjvjhOdd4j5Mp55GDAk2S7fWEw4JTC7aHq)

  
  <br>
  
  

> Enter the following command to download the installation script. Please enter the code as a single line.
```bash
wget -q https://github.com/SINOVATEblockchain/SIN-core/releases/latest/download/din_install_vps_noroot.sh
```
  
  <br>
  

![](assets/img/misc/din-setup-guide04.png)

  
  

> Enter the code below for authorization after the script is downloaded.

  
```bash
chmod +x  din_install_vps_noroot.sh
```
  
  

![](assets/img/misc/din-setup-guide05.png)

  
  

> Enter the code below to run the script.

  
  
```bash
./din_install_vps_noroot.sh
```
  
  
  

![](assets/img/misc/din-setup-guide06.png)

> Setup will ask for a username. If you hit enter, it will name the default sinovate.  
In our example, we used the name testuser1.

  

![](https://lh4.googleusercontent.com/CBmhWTL98vX4hl2W5ToyEM5XhisbOttfdX3nQFMd6zgbkjPLxgYcapedC2bWHfyLAV9lgyKxI9C-nuzSFwXaBZBiaobbf53VPRYkkfnXiHOmDeRYU6iW2jHppQsiDUl0ZDvl_Ufu)

  <br>
    
> At this stage, the installation will ask you to enter a password for the new user. Please choose a strong password and do not share it with anyone.  
  
> The script disables root user VPS access for security.

<br>
  

![](https://lh5.googleusercontent.com/1DYyM9XutnrpEN1brhbZhC58ncumEunkdWpQFuFTMVQ_dLu3jmok6VOfifcwT5lFJvk0L8-6AIoHRWfq5dAN4ffQq9YcpEieMLq0VSFt30tR0rzHkO7_DkdKih_ULy8ovQAO6c5y)

  <br>

![](https://lh3.googleusercontent.com/hSXi1G6pwxgos6u7kmEhoFUORBE_6EQHnQsaZUIn6pvRGJCOsJVGe8YmFzI2vMryyG7bAco2wRqj069gkWoJL1JMXfh1xSHXrSWG1QeUydpaTU8VEnHAmD40lMBEyy-JPTFsFgmo)  
  
  <br>
  
> It is completed in 5-10 minutes after the installation starts. Please be patient.

  

![](https://lh6.googleusercontent.com/5ojbTwMOVqLszlVEI2Xl5gR7k52DVKIdTmdLwQvT1RaTTkm0slXwA6w2CfZUMJ-V8UBoPZTNEQ6ICM8hwHWbZ4McHkF9tArRapdSJg0Q-On-tVIaWaY7YQNq37S1NF4MNtOH8dui)

  <br>

> At this stage, the SIN daemon runs automatically for the first time.  
Also, the private key given by VPS is imported to the address given by VPS.

![](https://lh4.googleusercontent.com/KZw4L5Z8xd7jFE9PUkk0XX-uQOzf5GgyjmxkJ7wGtuTBTMRmxUhLzQ9UyK5WLAtsmpKsBSO0w5UD9xFWeIdRX3UgwH7ddxCiYi0qSLg874mXqgjY2yPDcglEdxC6n628-wiTQ4WS)

  <br>
  
> When the installation is completed, an information screen like the one below appears.  
  
  <br>
  
> Please save the given keys and address information. You can do this by choosing with the mouse. PuTTY and similar programs also copy the selected area to the clipboard. This information will be required in the later stages of the installation.

  

![](https://lh5.googleusercontent.com/F_aurcOEBKQvoVHgJAJuDmkNGAVgq1VIBRLrEIaq53TU0mrI3c7T4FM0MVF7vLhht-rzdcFXCD7dB_X68fRDrHZRowmSocYqlcj53job2hU02FnMtj9kwKfxrSwM9qnkOhKUYzYD)

<br>  

![](https://lh4.googleusercontent.com/VtXV5A4V3S5ScoO2jdbsP_AqTXrnXcJ7Z_xJX0P6oEQ86rGfdOx6IZSKOgQ9dPnwgdO_EJk7v4E-N0Qw2sSaWuT0qjPY-yVvFot55_w0xA5aTZC7pZEha1kc7RckbITdMRqi9qh1)

<br>
  
```bash
reboot
```
  
  <br>

> Return to your control wallet and create a new receiving address.  
In our example, BIG D.I.N. we will create.

![](https://lh4.googleusercontent.com/Ez_HbBZAoLN0ZeodFVdN9_v8OpHpUPEGSVFsQUdoX2hCQM8XxYg2Ing_19QBPMD_TfOlg3oHzNRIqLAtC6CllbxhBmHPR4WNPESEgDDMkK7TvxsU9yZof3v9v_gLDyzP4zQ8UQhw)

  <br>

![](https://lh4.googleusercontent.com/VZjeoQuGmoF72vwMTljy3TJQUVtEC9upj-mblc9ZIjpnlRBiJnLto1URof5uKttyIHTgStNA6-sY6TcpKvdsSMaqezn7eU5GQXE1PPRx9Nx5dQN5ZHmd4auSMKoME3nR2IeThnc8)

  <br>

> Copy the new address you create and send it exactly 1 000 000 SIN to this address.  

|Type DIN     | Amount      | 
|----------|--------------|
|BIG DIN|1 000 000 for|
|MID DIN| 500 000 for|
|MINI DIN| 100 000 for|

You should send.
     


![](https://lh4.googleusercontent.com/1kmD68GdwNwGUPieLK-94xDeEW6dt3ImKib0ZdL09sl-9F0jjzUecQG2kWYpQn2kJQ-kbAv-LuhizKjYzWJOfl6aRhthQc-LMwHQ-1WL6C8cixVGjgazI5ncqSZwyxXTp8T_ef5d)

   <br>

> Please wait for 2 confirmations!

  
 <br>
  

![](https://lh4.googleusercontent.com/7c-j71N5XCcdpRGD8He_pnQGlVN8wVWKJjoYqu05ymMYU1mgKdL9RsWEPaKXCf5j2lnN6Z76LBEcOaRVMVteQ-tttScfvd6eNKM1yBjbOqZoqZaXZ2aABW9GUCFug-1_G0sNpUwD)

<br>  

walletpassphrase [passphrase] [timeout]

  

![](https://lh3.googleusercontent.com/nWW7RtXnYJahewiiHVsnec3IRQg2otk8hzLS2PYKXIbH-eLrSyAyHdUbkmGHUSBtl7Zq1FCbqsfdvczMuoPtdd4K6VxMrumtQ6gCiIILwJ4ALkQ6Jt9TId6G4o6dAxWUrNpmr0BV)

  
  <br>

```bash
infinitynodeburnfund [YourAddress] [Amount 1M / 500K / 100K] [YourBackupAddress]
```
<br>

> :information_source:
> YourBackupAddress will let the node owner change the receiving address of the node if the user node gets in the hands of malicious actors.
  
  <br>

![](https://lh3.googleusercontent.com/ziXM81BBEJm5UNE616GVJp97yphj6OWUAH-cAK-jHPOLtBPtVngkg2RMkU6Gj43d6Sma45akLybz-2rB4XMBSTgOuz6C5iOJ0keP38DCIZefnH1T-1d9sv2nUs5wL6WyP2H0HcWf)

  <br>

![](https://lh5.googleusercontent.com/xDTY2qdwg4YNusxTaJCdZ9uYw_H9tgwYAegtdZMbtxt3a5jz_Sm7MkX2H7uGMxwOixx-GSROEOsrc6QFLtsLG-MbZ-xhNurG5Ku5mbR09Ur2xXZRbEUppwICbBqif6yKmLgHingX)

  <br>

![](https://lh4.googleusercontent.com/kRDvCICKRA45NxYBbhPbIE7bJ92FxokmqN1ysXxiBnC3poPYPRWihfcPRAbUFzb1U22Pp_OjsDwuHGeHS8HJJLo5Z4cv8sKYQ8wbgaYxqleVbWs-tceMqYYWlgA_hmP9yJzSltS2)

  <br>

![](https://lh4.googleusercontent.com/PrFINr0C-L-exsHOVWgfoYyL-7XzYm8rfNnmNVQnpclbu30xOX3DYQaEeO6UkDm-L2c6BkJpUpnVjQPtwVVgnl0VuL3h09vGcWVQ_3qjW_2unHNLRU2Dj5gwh6AS6Mjr5_hAHtWc)

<br>
  
**Send 3 SINs to DIN Node address.**

![](assets/img/send3sin.png)

  <br>
  

![](https://lh3.googleusercontent.com/7ntvMjgCOelzwj3UFkSlPJEUyEBkR-hYLgWlIW0uJwZMQ57_iFzL4KGo1lM6cYHGzSe6xYwlnGEp-EMCBsVvd7T5T1b8z4lwv5aepYdYSBjsW_MT7UWWyNQXyoywmLaUm43wTTUm)
  <br>

Please wait for 2 confirmations!

<br>

![](assets/img/misc/din-setup-guide24.png)
  
<br>

Please wait for 2 confirmations!

  
  
```bash
infinitynodeupdatemeta [Owner address] [node PublicKey] [node IP]:20970 [first 16 characters of BurnFundTx]
```

<br>

> :warning: **Please do not use the information generated by keypair on the VPS twice.***
 If you think something is wrong, go back to VPS and create a new keypair with the command ``` ./sin-cli infinitynode keypair```. Repeat the processes on this keypair.
Remember, using the new keypair requires you to update the infinitynodeprivkey info in your sin.conf file on the VPS and restart the daemon.
 
 <br>
  

![](https://lh5.googleusercontent.com/kVl_Xf6DoFAMYHBFpWxfWP20Ff3eXVo7gobwSDD6QvQnxSJKtHQOCzal6VZ3-JbGWiVdEz5fOBjJiZ9-ZtBC0ri5bgwGw8zhuJY6Y5a0stv7XJLa6MIc_Jx8uy-31g8rqDbLOQmx)

<br>

![](https://lh4.googleusercontent.com/Uj_Ai81h0KrKMP03WiYqepdxBbb67GreIu93ZtsFsOHk82dH4s1A5omtMqZvq6ywbQuUheDAhZCxtt0yTNTJJpc6jB2ehVT5uEsyQaySA6NT0FRT4N56zfsP_JsfmJZ8KHtPVSEv)  

<br>
  
![](https://lh3.googleusercontent.com/G1SJ9fWetyv2x7hBYXWIf5UTPODdVgY4G95UhIMkETZAVWD_e5XtqNcL_7vFBib4OazyeHqe_Sph9T6O2FmZGD86CPzwAIWFIkmYE__hPIdtVWK23CVHlKQaU6wzTmfTn3wsClUk)

<br>

**Wait for 55 confirmations for DIN nodes to show up**

<br>

On vps Enter the command 

```bash
./sin-cli infinitynode mypeerinfo
```

<br>

If you are not getting an error and it still doesn't appear, on the console enter the `` infinitynode build-list`` command and wait.

:warning: This command will scan the entire chain from the beginning. In the meantime, your wallet may not respond. This process can take a few hours, depending on the number of transactions in your wallet. Please be patient.

<br>
  

**Congratulations. Your Deterministic Infinity Node is ready!**
