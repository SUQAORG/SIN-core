SIN (X25X Algo) Mining Using T-Rex Miner

1-  Download T-Rex Latest Release

Download the current T-Rex version for your Nvidia graphics card.

Cuda 10 is preferred.

[https://github.com/trexminer/T-Rex/releases](https://github.com/trexminer/T-Rex/releases/tag/0.19.14)

![](assets/img/x25x_pow_gpu_mining/1.png)

2-  Update Nvidia GPU Driver

If your video card driver is not up-to-date, it is recommended that you update it from the following address.

[https://www.nvidia.com/Download/index.aspx?lang=en-us](https://www.nvidia.com/Download/index.aspx?lang=en-us)

![](assets/img/x25x_pow_gpu_mining/2.png)

  

3-  Creating a sample start.bat file

Go to the folder located in the T-Rex miner.

![](assets/img/x25x_pow_gpu_mining/3.png)

  
  
  
  

Open a new Text Document

Server addresses by region are given below…

Europe stratum:

[t-rex](https://github.com/trexminer/T-Rex/releases/tag/0.19.14) -a x25x -o stratum+tcp://eupool.sinovate.io:3253 -u <WALLET_ADDRESS>.%COMPUTERNAME% -p c=SIN

Asia stratum:

[t-rex](https://github.com/trexminer/T-Rex/releases/tag/0.19.14) -a x25x -o stratum+tcp://asiapool.sinovate.io:3253 -u <WALLET_ADDRESS>.%COMPUTERNAME% -p c=SIN

USA stratum:

[t-rex](https://github.com/trexminer/T-Rex/releases/tag/0.19.14) -a x25x -o stratum+tcp://uspool.sinovate.io:3253 -u <WALLET_ADDRESS>.%COMPUTERNAME% -p c=SIN

  

We used the European server in our example.

Please do not forget to write your own wallet address.

![](assets/img/x25x_pow_gpu_mining/4.png)

Select Save as and name the start.bat file.

![](assets/img/x25x_pow_gpu_mining/5.png)

4-  Start the mining

Please double-click the start.bat file you just created. The T-Rex will connect to the server of your choice and start mining.

  

![](assets/img/x25x_pow_gpu_mining/6.png)

For more detailed use of the T-Rex Miner, please see the Readme file at [https://github.com/trexminer/T-Rex](https://github.com/trexminer/T-Rex)
