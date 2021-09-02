# cece

## なにこれ？

.env ファイルの暗号化ツール

## .env ファイル

下記のようなファイルです。

```text:.env
a=hoge
b=fuga
# comment
c=3
```

暗号化すると以下のようになります。

```text:.env.crypto
a=sha256-aes128-cbc:bmgMcZHqealXxOJ4A9Ts0RxLFNwoksrWCmATMh1NbpM=::4qGvFxLU5z7DwOYjVyKTPA==
b=sha256-aes128-cbc:GzLD/dlQPga0mJPdr5fqjZOX7tb64N4J2hY/v1Bv1bI=::eILNAC7qL8CkjH7E6mIZJg==
# comment
c=sha256-aes128-cbc:iFE29JJzQCzLsh8Il4TKczby4BlaSHasvs4pi0j2dlw=::wzovCasaG7a39qBJ3wn7WA==
```

## 特徴

- 行ごとに暗号化するので、差分がわかりやすい
- 行ごとに暗号アルゴリズムを変更できる
  - 現状復号のみ

## 改良予定

- 差分行のみ暗号化
