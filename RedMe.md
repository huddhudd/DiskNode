NvCache 文件保存位置 D:\CloudDiskCache\NvphData\00\7c   后面两层是Hash 前4位
需要注意D:\ 这个是通过 CloudStart.ini [UserCache]
1=D:\
2=E:\
来获取的。 如果有多个盘时，你需要定时维护每一个盘的剩余空间大小。哪个大就保存在哪里

着色器清单保存在 当前目录 ./Data/NvphLists
./NvphLists/Seats  每一个机器的清单保存在这里。 注意 
./NvFiles.db 里面表 就只有Hash 与 Count，是用于来计数的，用于清除没有引用的的所有文件使用。 当用户拉取清单时执行清理，维护计数。如果没有拉也还有一个定时1天清理一次。
收到

NV的所有逻辑与C++完全相同。  解析清单代码demo\filelist.go 可以作为生成清单的参考。
注意:所有C++的细节都需要处理,特别是清理

整个项目目录在 Z:\qihao\CloudApp\UserDoc\UserDocServer\  NvCache源码 Z:\qihao\CloudApp\UserDoc\UserDocServer\









Z:\qihao\CloudApp\UserDoc\UserDocServer\UserSave.h  是云启动项目的一部份。 

用户存档API.txt 要提供的 webAPI
用户存档ClientAPI.txt 要提供的客户端API

之前是SqlLite 来维护清单。

但现在我需要改成通过文件来维护。 

说明:
上传文件时都在临时目录  d:\CloudDiskCache\TmpData  这里的D:\只是例子。GetCacheDataDirs里的所有盘。 
用户断开/拉清单时。后就开始入库。
生成新的版本，每一个用户最多生成9版本，
生成到程序目录下  0 代表前版本  程序放在CloudServer\里面
\CloudServer\Data\UserList\UID\RuleID.json
\CloudServer\Data\UserList\123\578080\1.json
\CloudServer\Data\UserList\123\578080\2.json
\CloudServer\Data\UserList\123\578080\3.json
\CloudServer\Data\UserList\123\578080\4.json
\CloudServer\Data\UserList\123\578080\5.json
\CloudServer\Data\UserList\123\578080\6.json
\CloudServer\Data\UserList\123\578080\7.json
\CloudServer\Data\UserList\123\578080\8.json
\CloudServer\Data\UserList\123\578080\9.json

新的生成，需要读取最大的ID版 \CloudServer\Data\UserList\9.json
然后根据临时目录的
 
当入库时，需要更新表中的Count。 
SqlLite表结构 Hash  Count 
清理与删除存档时 减少Count 如果Count=0 时删除文件与数据库中的记录。 
d:\CloudDiskCache\ArchData\00  所有可能保存在每一个盘中的CloudDiskCache目录下的ArchData 

CDataFactory::Get()->GetCacheDataDirs(vCcDirs);  vCcDirs是所有的盘


这个后端以前是插件的方式运行的。 我想用GO来实现这个功能。 独立运行

项目的原来的目录是Z:\qihao\CloudApp\ 根目录
UserDoc\UserDocServer里面有所有需要用于的引用
 