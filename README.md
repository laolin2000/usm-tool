# USM Tool

> CRI USM（Sofdec2）影片解包与重建：.dat → IVF → ffmpeg → MP4

## 运行方式

```
python usm_extract.py <input>  &&  node ivf-rebuild.mjs   # 完整脚本清单见 README
```

## 说明

- 成品视频（约 1.1 GB）与样本文件未入库；第三方 `wannacri` 工具链请从其上游获取。

## 关于本仓库

- 本仓库为个人项目备份，只包含**程序本体**：不含运行时数据、日志、缓存、构建产物与任何密钥。
- 配置中的密钥一律留空，请自行填入（或改用环境变量）。
- 路径中的 `C:\Users\<you>` 表示你自己的用户目录。
