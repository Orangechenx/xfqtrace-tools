# libsdk_bc_lib.so 签名算法逆向

## 概述

AppsFlyer SDK 的请求签名由 native 函数 `sub_0x2cc11c` 计算，最终输出为 HMAC-SHA256。

## 算法流程

```
signature = HMAC-SHA256(key_bytes, message_bytes)
```

### Message 计算

```
message = SHA-256(request_body_bytes)   // x3 参数，序列化后的请求体
message_bytes = bytes.fromhex(message)
```

### Key 计算

```python
# 常量
SHA256_XVZ = SHA-256(bytes[0x78, 0x56, 0x5a])
           = "9803667766d346ad0805c3e58209fa50b5ef58fd32ff43a4b9e1f68f7ed72241"

HASH2 = SHA-256(SHA-256(SHA-256("f4e")[3:39])[0:41])
       = "3416aae432e69c4350ad27274f173d7c44a1cdf4aa49b90598884a0bf41704b2"

# 动态计算
sha1 = SHA-256(hex_string)                                          # hex_string 128字符，来自Java层
sha3 = SHA-256(uuid + brand + hex_string + sha1 + package + SHA256_XVZ)  # 309 bytes
sha5 = SHA-256(sha3 + sha1[4:28])                                   # 88 bytes

key = SHA-256(sha5 + HASH2 + counter + "null" + af_timestamp + uid) # 180 bytes
key_bytes = bytes.fromhex(key)
```

### 参数说明

| 参数 | 示例值 | 来源 |
|------|--------|------|
| hex_string | `b4d1801d...49cb82ea` (128 chars) | Java层传入 (x2参数)，由map中多个字段的SHA-256拼接而成 |
| uuid | `90e906c5-2bc4-4927-82c6-d8b5a337864b` | 设备标识符（非advertiserId） |
| brand | `google` | Build.BRAND |
| package | `ru.moneyman` | 应用包名 |
| counter | `71` | 请求计数器 |
| "null" | 字面量字符串 | firstLaunchDate 为空时的占位符 |
| af_timestamp | `1780087283534` | AppsFlyer 时间戳 |
| uid | `1779998303386-8958264294592850740` | AppsFlyer UID |

## 验证

```python
import hashlib, hmac

hex_string = "b4d1801d1cd609767a0b9a5277da0d80e9655c4f917c1dd78d44b20a0701c2524d10929b925adbb8b22a0e479bd31b95ec58d5f744b08881ab17f9ab49cb82ea"
uuid_val = "90e906c5-2bc4-4927-82c6-d8b5a337864b"
brand = "google"
pkg = "ru.moneyman"
counter = "71"
firstLaunchDate = "null"
af_timestamp = "1780087283534"
uid = "1779998303386-8958264294592850740"

SHA256_XVZ = "9803667766d346ad0805c3e58209fa50b5ef58fd32ff43a4b9e1f68f7ed72241"
HASH2 = "3416aae432e69c4350ad27274f173d7c44a1cdf4aa49b90598884a0bf41704b2"

sha1 = hashlib.sha256(hex_string.encode()).hexdigest()
sha3 = hashlib.sha256((uuid_val + brand + hex_string + sha1 + pkg + SHA256_XVZ).encode()).hexdigest()
sha5 = hashlib.sha256((sha3 + sha1[4:28]).encode()).hexdigest()
key = hashlib.sha256((sha5 + HASH2 + counter + firstLaunchDate + af_timestamp + uid).encode()).hexdigest()

# message = SHA-256(request_body)
message = "487fe65580c703000bffdf4b31b047cb07dc2e62c7dade4adb465a475b91badb"

signature = hmac.new(bytes.fromhex(key), bytes.fromhex(message), hashlib.sha256).hexdigest()
# = "07893f3b9f0d1e5617edd347701cb203fff0f42ee18a5d2184701e0540257013" ✓
```

## 待解决

1. **hex_string 的生成逻辑** — 128字符的hex字符串由Java层生成，是map中多个字段值的SHA-256拼接。需要逆向Java层确定具体哪些字段参与、拼接顺序。
2. **uuid 的来源** — `90e906c5-2bc4-4927-82c6-d8b5a337864b` 不是 advertiserId，需要确认是哪个设备标识。
3. **values 拼接规则** — counter + "null" + af_timestamp + uid 的选取和排列规则。

## 函数签名

```
sub_0x2cc11c(JNIEnv* env, jobject thiz, jbyteArray hex_string_bytes, jbyteArray request_body, jobject params_map)
```

- x2: hex_string 的 byte[] 形式
- x3: 请求体的 byte[] (用于计算 message)
- x4: HashMap，包含 counter/af_timestamp/uid/brand/package 等字段
