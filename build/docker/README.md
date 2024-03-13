- [Build NJet image](#build-njet-image)    
    - [Manual](#manual)
    - [Automatic](#automatic)
- [Run NJet](#run-njet)  
    - [Least Privileged](#least-privileged)
    - [Privileged](#privileged)
       

# Build NJet image
## Manual
下载njet_main源码
```sh
cd njet_main
export NJET_RIEPOSITORY="tmlake/njet"
export NJET_TAG="latest"
docker build --build-arg NJet_VERSION=$NJET_TAG --build-arg GIT_COMMIT=$(git rev-parse HEAD)  --network host --target ubuntu-njet -f ./build/docker/Dockerfile_njet -t $NJET_RIEPOSITORY:$NJET_TAG ./ 
```

## Automatic
支持gitlab CI构建，脚本详见.gitlab-ci.yml    


# Run NJet
## Least Privileged
出于安全考虑，在运行NJet容器时，我们推荐使用最小特权启动容器。容器具有指定的能力。
执行如下命令启动NJet。
```sh
docker run  -d --rm --cap-drop=ALL --cap-add=cap_dac_override --cap-add=cap_dac_read_search --cap-add=cap_setuid --cap-add=cap_net_bind_service --cap-add=cap_net_admin --cap-add=cap_net_raw --cap-add=cap_setgid --cap-add=cap_audit_write tmlake/njet:latest
```
```
--cap-add=cap_setgid 与
--cap-add=cap_audit_write 可以使用sudo，比如sudo iptables -t nat -S
```

挂载宿主机文件，执行如下命令启动NJet。
```
docker run -v /root/liuqi/njet/njet.conf:/usr/local/njet/conf/njet.conf -v /root/liuqi/njet/njet_ctrl.conf:/usr/local/njet/conf/njet_ctrl.conf -v /root/liuqi/njet/logs:/usr/local/njet/logs -v /root/liuqi/njet/data:/usr/local/njet/data  -d  --rm --cap-drop=ALL --cap-add=cap_dac_override --cap-add=cap_dac_read_search --cap-add=cap_setuid --cap-add=cap_net_bind_service --cap-add=cap_net_admin --cap-add=cap_net_raw --cap-add=cap_setgid --cap-add=cap_audit_write tmlake/njet:latest
```

## Privileged
也可以使用privileged启动容器，容器继承内核所有的能力。
执行如下命令启动NJet。
```sh
docker run  -d --rm --privileged  tmlake/njet:latest
```

