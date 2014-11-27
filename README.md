DrCOM 802.1X
=====

**注意本脚本不支持 Windows 和 MacOS**

这个脚本需要修改的地方

1. `main.py` 中的 `username`, `password`, `ethernet_interface`, 其中 `username`, `password` 为上网账号密码， `ethernet_interface` 为 WAN 口设备接口.
2. 确认学校是否仅需要 `802.1X` 认证， 这是可以试出来的， 可尝试将 `main.py` 中 `need_drcom` 改成 `True` 或 `False` 实验，该变量为 `True` 时，会附加 `DrCOM` 认证，而不仅仅是作 `802.1X` 认证
3. 如果需要 `DrCOM` 认证，请您访问 <https://github.com/drcoms/generic/blob/master/latest-wired.py> 获取最新的认证脚本，并将该脚本文件名改为 `drcom.py` 并且按说明正确配置相关文件
4. 注意，该项目的 `drcom.py` 将不起到 `DrCOM` 认证作用，请按 3 中方法实施。

认证请执行 `main.py`
