# Service

`CertService` 包含了生成密钥、生成 CSR、获取证书、签名 CSR、撤销证书和导出 PKCS#12 等功能，基于[kratos](https://github.com/go-kratos/kratos)实现：


1. **生成密钥**：`GenKey` 方法用于生成一个新的私钥，并返回其字符串表示。
2. **生成 CSR**：`CSR` 方法用于生成一个新的 CSR，并返回其字符串表示。
3. **获取证书**：`GetCert` 方法从存储库中获取证书，如果证书不存在或获取失败，则返回错误。
4. **签名 CSR**：`CASignCSR` 方法使用 CA 的私钥和证书签名 CSR，并保存生成的证书。
5. **撤销证书**：`RevokeCert` 方法用于撤销证书，包括加载当前 CRL、创建新的 CRL、更新 CRL、保存 CRL 等操作。
6. **导出 PKCS#12**：`PKCS12` 方法用于生成 PKCS#12 格式的证书，并返回其字符串表示。

结构定义详见[cert.proto](../../api/goca/v1/cert.proto)。  

# TODO

- [ ] 证书撤销列表（CRL）更新
- [ ] 目前证书、私钥等在服务端是以`common`进行区分的，证书考虑以证书编号`serial_number`进行区分
- [x] `PKCS12`接口目前仅支持生成，后续需要增加导出的功能
- [ ] 多级证书签发功能
- [ ] 证书解析功能
- [ ] 私钥加密功能
  - [x] 3DES加解密功能已新增