# keycloak-service-social-lark
Keycloak social identity provider for Lark(飞书).


## Run with Jboss
1. 添加jar包到Keycloak服务:  
```
cp target/keycloak-service-social-lark-${version}.jar KEYCLOAK_HOME/standalon/deployments
```

2. 添加模板文件到Keycloak服务:  
```
cp templates/realm-identity-provider-lark.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials  
cp templates/realm-identity-provider-lark-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials     
```

## Run with Docker
直接使用dockerfile文件构建镜像，然后使用docker运行，参考命令：
```
docker run -d --name my-keycloak -p 8080:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin keycloak-with-lark:v1
```
>注：Dockerfile中构建镜像时，复制了`standalone.conf`文件。由于8.0.1版本的keycloak镜像的默认编码格式不是`UTF-8`，会导致飞书接口返回的中文字符乱码。在`standalone.conf`中给`JAVA_OPTS`配置了`file.encoding=UTF-8`，强制设置编码格式为`UTF-8`，以支持飞书接口返回的中文信息（如名字）。

## Others
based on https://github.com/zh417233956/keycloak-services-social-dingtalk  
based on https://github.com/litianzhong/keycloak-social-ding

