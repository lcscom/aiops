# OVA 어플라이언스 포함 OS 패키지 (Ubuntu 24.04 LTS)

`vcf-aiops-1.11.3.ova` 이미지에 설치된 Ubuntu 패키지 전체 목록입니다(262개 — 1.12.0·2.0.0 OVA 도 같은 262개로 확인). 첫 부팅한 어플라이언스에서 `dpkg-query` 로 뽑았고, 라이선스 칸은 각 패키지의 `/usr/share/doc/<패키지>/copyright`(DEP-5 형식)의 `License:` 값을 모은 것입니다. 형식이 DEP-5 가 아닌 패키지는 '이미지 안 copyright 파일 참조'로 표시했습니다.

- 주요 구성요소: 커널 `linux-image-6.8.0-146-generic`(GPL-2.0) · 부트로더 `shim-signed`(BSD-2-Clause)·`grub-efi-amd64-signed`(GPL-3.0+, Canonical 서명) · `open-vm-tools`(GPL-2.0·LGPL-2.1 등) · `python3.12`(PSF-2.0) · `openssl`(Apache-2.0) · `chrony`(GPL-2.0) · `ufw`(GPL-3.0).
- **소스 코드 제공**: 이 패키지들은 수정 없이 Ubuntu 공식 저장소(noble·noble-updates·noble-security)의 바이너리를 그대로 담았습니다. 대응하는 소스는 같은 버전으로 `apt-get source <소스 패키지>=<버전>` 또는 https://launchpad.net/ubuntu/+source/<소스 패키지> 에서 받을 수 있습니다. GPL·LGPL 패키지의 소스를 요청하면 OVA 배포일로부터 3년 동안 저장소 관리자가 같은 버전의 소스를 제공합니다.
- 어플라이언스 안에서 확인: `dpkg-query -W -f='${Package}\t${Version}\n'` · `cat /usr/share/doc/<패키지>/copyright`

| 패키지 | 버전 | 소스 패키지 | 라이선스(copyright 파일) |
|---|---|---|---|
| `adduser` | 3.137ubuntu1 | adduser | GPL-2+ |
| `apt` | 2.8.3 | apt | BSD-3-clause,Expat,GPL-2,GPL-2+ |
| `apt-utils` | 2.8.3 | apt | BSD-3-clause,Expat,GPL-2,GPL-2+ |
| `base-files` | 13ubuntu10 | base-files | 이미지 안 copyright 파일 참조 |
| `base-passwd` | 3.6.3build1 | base-passwd | GPL-2,public-domain |
| `bash` | 5.2.21-2ubuntu4 | bash | BSD-4-clause-UC,BSD-4-clause-UC and MIT-like,GFDL-NIV-1.3,GPL-2+,GPL-3+,GPL-3+ with Bison exception,Latex2e,MIT-like,permissive |
| `bash-completion` | 1:2.11-8 | bash-completion | GPL-2+ |
| `bind9-dnsutils` | 1:9.18.39-0ubuntu0.24.04.7 | bind9 | BSD-2-clause,BSD-3-clause,CC0-1.0,FSFAP,ISC,ISC or MPL-2.0,MPL-2.0,MPL-2.0 and CC0-1.0,MPL-2.0 and ISC,MPL-2.0 and ISC and BSD-2-clause a… |
| `bind9-host` | 1:9.18.39-0ubuntu0.24.04.7 | bind9 | BSD-2-clause,BSD-3-clause,CC0-1.0,FSFAP,ISC,ISC or MPL-2.0,MPL-2.0,MPL-2.0 and CC0-1.0,MPL-2.0 and ISC,MPL-2.0 and ISC and BSD-2-clause a… |
| `bind9-libs` | 1:9.18.39-0ubuntu0.24.04.7 | bind9 | BSD-2-clause,BSD-3-clause,CC0-1.0,FSFAP,ISC,ISC or MPL-2.0,MPL-2.0,MPL-2.0 and CC0-1.0,MPL-2.0 and ISC,MPL-2.0 and ISC and BSD-2-clause a… |
| `bsdutils` | 1:2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `busybox-initramfs` | 1:1.36.1-6ubuntu3.1 | busybox | 이미지 안 copyright 파일 참조 |
| `ca-certificates` | 20260601~24.04.1 | ca-certificates | GPL-2+,MPL-2.0 |
| `chrony` | 4.5-1ubuntu4.2 | chrony | GPL-2,GPL-2+,RSA-MD |
| `cloud-guest-utils` | 0.33-1 | cloud-utils | GPL-3 |
| `coreutils` | 9.4-3ubuntu6 | coreutils | BSD-4-clause-UC,FSFULLR,GFDL-NIV-1.3,GPL-3+,GPL-3+ and BSD-4-clause-UC,GPL-3+ and ISC,ISC |
| `cpio` | 2.15+dfsg-1ubuntu2.1 | cpio | GPL-3+,LGPL-3+ |
| `curl` | 8.5.0-2ubuntu10.15 | curl | BSD-3-Clause,BSD-3-clause,BSD-4-Clause-UC,FSFULLR,GPL-2+ with Autoconf-data exception,GPL-2+ with Libtool exception,GPL-3+ with Autoconf-… |
| `dash` | 0.5.12-6ubuntu5 | dash | BSD-3-Clause,BSD-3-clause,GPL-2+,public-domain |
| `dbus` | 1.14.10-4ubuntu4.1 | dbus | AFL-2.1,BSD-3-clause,BSD-3-clause and BSD-3-clause-generic,BSD-3-clause-generic,Expat,FSF-unlimited-permission,GPL-2+,GPL-2+ or AFL-2.1, … |
| `dbus-bin` | 1.14.10-4ubuntu4.1 | dbus | AFL-2.1,BSD-3-clause,BSD-3-clause and BSD-3-clause-generic,BSD-3-clause-generic,Expat,FSF-unlimited-permission,GPL-2+,GPL-2+ or AFL-2.1, … |
| `dbus-daemon` | 1.14.10-4ubuntu4.1 | dbus | AFL-2.1,BSD-3-clause,BSD-3-clause and BSD-3-clause-generic,BSD-3-clause-generic,Expat,FSF-unlimited-permission,GPL-2+,GPL-2+ or AFL-2.1, … |
| `dbus-session-bus-common` | 1.14.10-4ubuntu4.1 | dbus | AFL-2.1,BSD-3-clause,BSD-3-clause and BSD-3-clause-generic,BSD-3-clause-generic,Expat,FSF-unlimited-permission,GPL-2+,GPL-2+ or AFL-2.1, … |
| `dbus-system-bus-common` | 1.14.10-4ubuntu4.1 | dbus | AFL-2.1,BSD-3-clause,BSD-3-clause and BSD-3-clause-generic,BSD-3-clause-generic,Expat,FSF-unlimited-permission,GPL-2+,GPL-2+ or AFL-2.1, … |
| `debconf` | 1.5.86ubuntu1 | debconf | BSD-2-clause |
| `debianutils` | 5.17build1 | debianutils | GPL-2+,SMAIL-GPL,public-domain |
| `dhcpcd-base` | 1:10.0.6-1ubuntu3.2 | dhcpcd | BSD-2,BSD-2-Clause-NETBSD,BSD-3-Clause,Expat,GPL-3+,ISC,public-domain |
| `diffutils` | 1:3.10-1build1 | diffutils | FSFAP,FSFULLR,GFDL-NIV-1.3,GPL-2+,GPL-3+,GPL-3+ and FSFULLR,GPL-3+ with autoconf exception,GPL-3+ with texinfo exception,LGPL-2.0+,LGPL-2… |
| `distro-info-data` | 0.72-0ubuntu0.24.04.1 | distro-info-data | ISC |
| `dosfstools` | 4.2-1.1build1 | dosfstools | GPL-3+,public-domain |
| `dpkg` | 1.22.6ubuntu6 | dpkg | GPL-2+,public-domain-s-s-d |
| `dracut-install` | 060+5-1ubuntu3.4 | dracut | BSD-3-clause,GPL-2+,LGPL-2.1+ |
| `e2fsprogs` | 1.47.0-2.4~exp1ubuntu4.1 | e2fsprogs | Apache-2,BSD-3-Clause,GPL or MIT-US-export,GPL-2,GPL-2+ with Texinfo exception,ISC,Kazlib,LGPL-2,Latex2e |
| `efibootmgr` | 18-1build2 | efibootmgr | GPL-2.0+ |
| `ethtool` | 1:6.7-1build1 | ethtool | GPL-2,GPL-3+ with autoconf exception |
| `fdisk` | 2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `findutils` | 4.9.0-5build1 | findutils | BSD-3-clause,BSD-3-clause and/or GPL-3+,FSFAP,FSFULLR,GFDL-NIV-1.3+,GPL with automake exception,GPL-2+,GPL-2+ with Autoconf-data exceptio… |
| `gcc-14-base` | 14-20240412-0ubuntu1 | gcc-14 | 이미지 안 copyright 파일 참조 |
| `gdisk` | 1.0.10-1build1 | gdisk | LGPL-2.0+ |
| `gettext-base` | 0.21-14ubuntu2 | gettext | 이미지 안 copyright 파일 참조 |
| `gpg` | 2.4.4-2ubuntu17 | gnupg2 | BSD-3-clause,CC0-1.0,Expat,GPL-2+,GPL-3+,GPL-3+ or BSD-3-clause,LGPL-2.1+,LGPL-3+,LGPL-3+ or GPL-2+,RFC-Reference,TinySCHEME,permissive |
| `gpgconf` | 2.4.4-2ubuntu17 | gnupg2 | BSD-3-clause,CC0-1.0,Expat,GPL-2+,GPL-3+,GPL-3+ or BSD-3-clause,LGPL-2.1+,LGPL-3+,LGPL-3+ or GPL-2+,RFC-Reference,TinySCHEME,permissive |
| `gpgv` | 2.4.4-2ubuntu17 | gnupg2 | BSD-3-clause,CC0-1.0,Expat,GPL-2+,GPL-3+,GPL-3+ or BSD-3-clause,LGPL-2.1+,LGPL-3+,LGPL-3+ or GPL-2+,RFC-Reference,TinySCHEME,permissive |
| `grep` | 3.11-4build1 | grep | GPL-3+ |
| `grub-common` | 2.12-1ubuntu7.3 | grub2 | CC-BY-SA-3.0,Expat,GPL-3+ |
| `grub-efi-amd64` | 2.12-1ubuntu7.3 | grub2-unsigned | CC-BY-SA-3.0,Expat,GPL-3+ |
| `grub-efi-amd64-bin` | 2.12-1ubuntu7.3 | grub2-unsigned | CC-BY-SA-3.0,Expat,GPL-3+ |
| `grub-efi-amd64-signed` | 1.202.5+2.12-1ubuntu7.3 | grub2-signed | GPL-3+ |
| `grub2-common` | 2.12-1ubuntu7.3 | grub2 | CC-BY-SA-3.0,Expat,GPL-3+ |
| `gzip` | 1.12-1ubuntu3 | gzip | FSF-manpages,GFDL-1.3+-no-invariant,GPL-3+ |
| `hostname` | 3.23+nmu2ubuntu2 | hostname | GPL-2 |
| `init-system-helpers` | 1.66ubuntu1 | init-system-helpers | BSD-3-clause,GPL-2+ |
| `initramfs-tools` | 0.142ubuntu25.8 | initramfs-tools | 이미지 안 copyright 파일 참조 |
| `initramfs-tools-bin` | 0.142ubuntu25.8 | initramfs-tools | 이미지 안 copyright 파일 참조 |
| `initramfs-tools-core` | 0.142ubuntu25.8 | initramfs-tools | 이미지 안 copyright 파일 참조 |
| `iproute2` | 6.1.0-1ubuntu6.4 | iproute2 | GPL-2 |
| `iptables` | 1.8.10-3ubuntu2 | iptables | Artistic,GPL-2,GPL-2+,custom |
| `iputils-ping` | 3:20240117-1ubuntu0.1 | iputils | BSD-3-clause,GPL-2+,public-domain |
| `klibc-utils` | 2.0.13-4ubuntu0.2 | klibc | 이미지 안 copyright 파일 참조 |
| `kmod` | 31+20240202-2ubuntu7.2 | kmod | GPL-2+,LGPL-2.1+ |
| `less` | 590-2ubuntu2.1 | less | GPL-3+,GPL-3+ or Less,GPL-3+ or Less, and X11,Less,Spencer-86,X11,public-domain |
| `libacl1` | 2.3.2-1build1 | acl | GPL-2+,LGPL-2+ |
| `libapparmor1` | 4.0.1really4.0.1-0ubuntu0.24.04.8 | apparmor | BSD-3-clause,BSD-3-clause or GPL-2+,GPL-2,GPL-2+,LGPL-2.1+ |
| `libapt-pkg6.0t64` | 2.8.3 | apt | BSD-3-clause,Expat,GPL-2,GPL-2+ |
| `libargon2-1` | 0~20190702+dfsg-4build1 | argon2 | Apache-2.0,CC0,CC0 or Apache-2.0 |
| `libassuan0` | 2.5.6-1build1 | libassuan | GAP,GAP~FSF,GPL-2+,GPL-2+ with libtool exception,GPL-3+,LGPL-2.1+,LGPL-3+ |
| `libattr1` | 1:2.5.2-1build1 | attr | GPL-2+,LGPL-2+ |
| `libaudit-common` | 1:3.1.2-2.1build1 | audit | GPL-2,LGPL-2.1 |
| `libaudit1` | 1:3.1.2-2.1build1 | audit | GPL-2,LGPL-2.1 |
| `libblkid1` | 2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `libbpf1` | 1:1.3.0-2build2 | libbpf | BSD-2-Clause,BSD-3-Clause,GPL-2 with Linux-syscall-note exception,GPL-2 with Linux-syscall-note exception OR BSD-3-Clause,GPL-2+,GPL-2.0,… |
| `libbrotli1` | 1.1.0-2build2 | brotli | MIT |
| `libbsd0` | 0.12.1-1build1.1 | libbsd | BSD-2-clause,BSD-2-clause-NetBSD,BSD-2-clause-author,BSD-2-clause-verbatim,BSD-3-clause,BSD-3-clause-John-Birrell,BSD-3-clause-Regents,BS… |
| `libbz2-1.0` | 1.0.8-5.1 | bzip2 | BSD-variant,GPL-2 |
| `libc-bin` | 2.39-0ubuntu8 | glibc | 이미지 안 copyright 파일 참조 |
| `libc6` | 2.39-0ubuntu8 | glibc | 이미지 안 copyright 파일 참조 |
| `libcap-ng0` | 0.8.4-2build2 | libcap-ng | GPL-2+,GPL-3,LGPL-2.1+ |
| `libcap2` | 1:2.66-5ubuntu2.4 | libcap2 | BSD-3-clause,BSD-3-clause or GPL-2,BSD-3-clause or GPL-2+,GPL-2,GPL-2+ |
| `libcap2-bin` | 1:2.66-5ubuntu2.4 | libcap2 | BSD-3-clause,BSD-3-clause or GPL-2,BSD-3-clause or GPL-2+,GPL-2,GPL-2+ |
| `libcbor0.10` | 0.10.2-1.2ubuntu2 | libcbor | Expat |
| `libcom-err2` | 1.47.0-2.4~exp1ubuntu4.1 | e2fsprogs | Apache-2,BSD-3-Clause,GPL or MIT-US-export,GPL-2,GPL-2+ with Texinfo exception,ISC,Kazlib,LGPL-2,Latex2e |
| `libcrypt1` | 1:4.4.36-4build1 | libxcrypt | 이미지 안 copyright 파일 참조 |
| `libcryptsetup12` | 2:2.7.0-1ubuntu4.2 | cryptsetup | Apache-2.0,CC0,CC0 or Apache-2.0,GPL-2+,GPL-2+ with OpenSSL exception,GPL-3+,LGPL-2.1+,LGPL-2.1+ with OpenSSL exception,public-domain |
| `libcurl4t64` | 8.5.0-2ubuntu10.15 | curl | BSD-3-Clause,BSD-3-clause,BSD-4-Clause-UC,FSFULLR,GPL-2+ with Autoconf-data exception,GPL-2+ with Libtool exception,GPL-3+ with Autoconf-… |
| `libdb5.3t64` | 5.3.28+dfsg2-7 | db5.3 | Artistic or BSD-3-clause,BSD-3-clause,BSD-3-clause-fjord,GPL,GPL or Artistic,GPL-3,MIT-old,Ms-PL,Sleepycat,Sleepycat and BSD-3-clause,TCL… |
| `libdbus-1-3` | 1.14.10-4ubuntu4.1 | dbus | AFL-2.1,BSD-3-clause,BSD-3-clause and BSD-3-clause-generic,BSD-3-clause-generic,Expat,FSF-unlimited-permission,GPL-2+,GPL-2+ or AFL-2.1, … |
| `libdebconfclient0` | 0.271ubuntu3 | cdebconf | BSD-2-Clause,BSD-2-clause,GPL-2+ |
| `libdevmapper1.02.1` | 2:1.02.185-3ubuntu3.2 | lvm2 | BSD-2-Clause,GPL-2.0,GPL-2.0+,LGPL-2.1 |
| `libdrm-common` | 2.4.125-1ubuntu0.1~24.04.2 | libdrm | 이미지 안 copyright 파일 참조 |
| `libdrm2` | 2.4.125-1ubuntu0.1~24.04.2 | libdrm | 이미지 안 copyright 파일 참조 |
| `libedit2` | 3.1-20230828-1build1 | libedit | BSD-3-clause |
| `libefiboot1t64` | 38-3.1build1 | efivar | GPL-2.0+,LGPL-2.0+ |
| `libefivar1t64` | 38-3.1build1 | efivar | GPL-2.0+,LGPL-2.0+ |
| `libelf1t64` | 0.190-1.1ubuntu0.1 | elfutils | BSD-2-clause,GFDL-NIV-1.3,GPL-3+,GPL-3+ with Bison exception,LGPL-2.1+,LGPL-3+ or GPL-2+ |
| `libexpat1` | 2.6.1-2ubuntu0.6 | expat | MIT |
| `libext2fs2t64` | 1.47.0-2.4~exp1ubuntu4.1 | e2fsprogs | Apache-2,BSD-3-Clause,GPL or MIT-US-export,GPL-2,GPL-2+ with Texinfo exception,ISC,Kazlib,LGPL-2,Latex2e |
| `libfdisk1` | 2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `libffi8` | 3.4.6-1build1 | libffi | Expat,GPL,GPL-2+,GPL-3+,MPL-1.1 or GPL-2+ or LGPL-2.1+,X11,public-domain |
| `libfido2-1` | 1.14.0-1build3 | libfido2 | BSD-2-clause,ISC,ISC and BSD-2-clause,public-domain |
| `libfreetype6` | 2.13.2+dfsg-1ubuntu0.2 | freetype | BSD-3-Clause,BSL-1.0,Expat,FSFAP,FTL,FTL and Expat,GPL-2+,GPL-3+,MIT-Modern-Variant,MIT-SMC,OpenGroup-MIT,Public-Domain,Zlib |
| `libfuse3-3` | 3.14.0-5build1 | fuse3 | GPL-2,GPL-2+,LGPL-2.1 |
| `libgcc-s1` | 14-20240412-0ubuntu1 | gcc-14 | 이미지 안 copyright 파일 참조 |
| `libgcrypt20` | 1.10.3-2build1 | libgcrypt20 | 이미지 안 copyright 파일 참조 |
| `libglib2.0-0t64` | 2.80.0-6ubuntu3.9 | glib2.0 | AFL-2.0,AFL-2.0 or LGPL-2.1+,Apache-2.0 with LLVM exception,CC-BY-SA-3.0,CC0-1.0,CC0-1.0 or Mingw-PD,Expat,FSFULLR,GPL-2+,Iconv-PD,Janik-… |
| `libgmp10` | 2:6.3.0+dfsg-2ubuntu6 | gmp | GPL-2+,GPL-2+ or LGPL-3+,GPL-3+,GPL-3+ with Bison exception,LGPL-3+ |
| `libgnutls30t64` | 3.8.3-1.1ubuntu3 | gnutls28 | Apache-2.0,BSD-3-Clause,CC0 license,Expat,GPLv3+,LGPLv2.1+,LGPLv3+_or_GPLv2+,The main library is licensed under GNU Lesser |
| `libgpg-error0` | 1.47-3build2 | libgpg-error | BSD-3-clause,GPL-3+,LGPL-2.1+,LGPL-2.1+ or BSD-3-clause,g10-permissive |
| `libgssapi-krb5-2` | 1.20.1-6ubuntu2.10 | krb5 | 이미지 안 copyright 파일 참조 |
| `libhogweed6t64` | 3.9.1-2.2build1 | nettle | Expat,GAP,GPL-2,GPL-2+,GPL-3+ with Autoconf exception,LGPL-2+,LGPL-3+,LGPL-3+ or GPL-2+,public-domain |
| `libibverbs1` | 50.0-2ubuntu0.2 | rdma-core | BSD-2-clause,BSD-2-clause or GPL-2,BSD-3-clause,BSD-3-clause or GPL-2,BSD-MIT,BSD-MIT or GPL-2,CC0,CPL-1.0,CPL-1.0 or BSD-2-clause or GPL… |
| `libicu74` | 74.2-1ubuntu3.1 | icu | GPL-3,MIT |
| `libidn2-0` | 2.3.7-2build1 | libidn2 | GPL-2+,GPL-3+,LGPL-3+,LGPL-3+ or GPL-2+,Unicode |
| `libinih1` | 55-1ubuntu2 | libinih | BSD-3-Clause |
| `libip4tc2` | 1.8.10-3ubuntu2 | iptables | Artistic,GPL-2,GPL-2+,custom |
| `libip6tc2` | 1.8.10-3ubuntu2 | iptables | Artistic,GPL-2,GPL-2+,custom |
| `libjson-c5` | 0.17-1build1 | json-c | Expat |
| `libk5crypto3` | 1.20.1-6ubuntu2.10 | krb5 | 이미지 안 copyright 파일 참조 |
| `libkeyutils1` | 1.6.3-3build1 | keyutils | GPL-2+,LGPL-2+ |
| `libklibc` | 2.0.13-4ubuntu0.2 | klibc | 이미지 안 copyright 파일 참조 |
| `libkmod2` | 31+20240202-2ubuntu7.2 | kmod | GPL-2+,LGPL-2.1+ |
| `libkrb5-3` | 1.20.1-6ubuntu2.10 | krb5 | 이미지 안 copyright 파일 참조 |
| `libkrb5support0` | 1.20.1-6ubuntu2.10 | krb5 | 이미지 안 copyright 파일 참조 |
| `libldap2` | 2.6.10+dfsg-0ubuntu0.24.04.1 | openldap | BSD-3-clause,BSD-3-clause-California,BSD-3-clause-variant,BSD-4-clause-California,Beerware,Expat,Expat-ISC,Expat-UNM,F5,FSF-unlimited,FSF… |
| `liblmdb0` | 0.9.31-1build1 | lmdb | OpenLDAP-2.8 |
| `liblz4-1` | 1.9.4-1build1 | lz4 | BSD-2-clause,GPL-2+,GPL-2+ or BSD-2-clause |
| `liblzma5` | 5.6.1+really5.4.5-1 | xz-utils | Autoconf,GPL-2,GPL-2+,LGPL-2.1+,PD,PD-debian,config-h,noderivs,none,permissive-fsf,permissive-nowarranty,probably-PD |
| `libmaxminddb0` | 1.9.1-1build1 | libmaxminddb | Apache-2.0,BSD-2-clause and BSD-3-clause and BSD-4-clause,CC-BY-SA-3.0,GPL-2+ |
| `libmd0` | 1.1.0-2build1 | libmd | BSD-2-clause,BSD-2-clause-NetBSD,BSD-3-clause,BSD-3-clause-Aaron-D-Gifford,Beerware,ISC,public-domain-md4,public-domain-md5,public-domain… |
| `libmnl0` | 1.0.5-2build1 | libmnl | GPL-2+,LGPL-2.1 |
| `libmount1` | 2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `libmspack0t64` | 0.11-1.1build1 | libmspack | LGPL-2.1 |
| `libncursesw6` | 6.4+20240113-1ubuntu2 | ncurses | BSD-3-clause,MIT/X11,X11 |
| `libnetfilter-conntrack3` | 1.0.9-6build1 | libnetfilter-conntrack | GPL-2+ |
| `libnetplan1` | 1.1.2-8ubuntu1~24.04.3 | netplan.io | GPL-3 |
| `libnettle8t64` | 3.9.1-2.2build1 | nettle | Expat,GAP,GPL-2,GPL-2+,GPL-3+ with Autoconf exception,LGPL-2+,LGPL-3+,LGPL-3+ or GPL-2+,public-domain |
| `libnfnetlink0` | 1.0.2-2build1 | libnfnetlink | GPL-2.0+ |
| `libnftnl11` | 1.2.6-2build1 | libnftnl | GPL-2,GPL-2+ |
| `libnghttp2-14` | 1.59.0-1ubuntu0.4 | nghttp2 | BSD-2-clause,Expat,GPL-3+ with autoconf exception,MIT,all-permissive |
| `libnl-3-200` | 3.7.0-0.3build1.1 | libnl3 | 이미지 안 copyright 파일 참조 |
| `libnl-route-3-200` | 3.7.0-0.3build1.1 | libnl3 | 이미지 안 copyright 파일 참조 |
| `libnpth0t64` | 1.6-3.1build1 | npth | LGPL-2.1+ |
| `libp11-kit0` | 0.25.3-4ubuntu2 | p11-kit | Apache-2.0,BSD-3-clause,FSFAP,FSFULLR,GPL-2+ with Autoconf-data exception,GPL-3+ with Autoconf-data exception,ISC,LGPL-2.1+,X11,customFSF… |
| `libpam-modules` | 1.5.3-5ubuntu5 | pam | BSD-3-clause or GPL,BSD-tcp_wrappers,Beerware,GPL-2,GPL-2+,GPL-3,GPL-3+ with Bison exception,LGPL-2+,public-domain |
| `libpam-modules-bin` | 1.5.3-5ubuntu5 | pam | BSD-3-clause or GPL,BSD-tcp_wrappers,Beerware,GPL-2,GPL-2+,GPL-3,GPL-3+ with Bison exception,LGPL-2+,public-domain |
| `libpam-runtime` | 1.5.3-5ubuntu5 | pam | BSD-3-clause or GPL,BSD-tcp_wrappers,Beerware,GPL-2,GPL-2+,GPL-3,GPL-3+ with Bison exception,LGPL-2+,public-domain |
| `libpam0g` | 1.5.3-5ubuntu5 | pam | BSD-3-clause or GPL,BSD-tcp_wrappers,Beerware,GPL-2,GPL-2+,GPL-3,GPL-3+ with Bison exception,LGPL-2+,public-domain |
| `libpcap0.8t64` | 1.10.4-4.1ubuntu3.1 | libpcap | 이미지 안 copyright 파일 참조 |
| `libpci3` | 1:3.10.0-2build1 | pciutils | GPL-2+ |
| `libpcre2-8-0` | 10.42-4ubuntu2 | pcre2 | BSD-2-clause,BSD-3-clause,BSD-3-clause-Cambridge with BINARY LIBRARY-LIKE PACKAGES exception,X11,public-domain |
| `libpng16-16t64` | 1.6.43-5ubuntu0.7 | libpng1.6 | Apache-2.0,BSD-3-clause,BSD-like-with-advertising-clause,GPL-2+,GPL-2+ or BSD-like-with-advertising-clause,expat,libpng,libpng OR Apache-… |
| `libpopt0` | 1.19+dfsg-1build1 | popt | GPL-2+,expat |
| `libproc2-0` | 2:4.0.4-4ubuntu3 | procps | GPL-2.0+,LGPL-2.0+,LGPL-2.1+ |
| `libpsl5t64` | 0.21.2-1.1build1 | libpsl | Chromium,MIT,gnulib |
| `libpython3-stdlib` | 3.12.3-0ubuntu2.1 | python3-defaults | 이미지 안 copyright 파일 참조 |
| `libpython3.12-minimal` | 3.12.3-1ubuntu0.17 | python3.12 | PSF-2.0(이미지 안 copyright 파일 참조) |
| `libpython3.12-stdlib` | 3.12.3-1ubuntu0.17 | python3.12 | PSF-2.0(이미지 안 copyright 파일 참조) |
| `libreadline8t64` | 8.2-4build1 | readline | GFDL-NIV-1.3+,GPL-2+,GPL-3,GPL-3+,ISC-no-attribution |
| `librtmp1` | 2.4+20151223.gitfa8646d.1-2build7 | rtmpdump | 이미지 안 copyright 파일 참조 |
| `libsasl2-2` | 2.1.28+dfsg1-5ubuntu3.1 | cyrus-sasl2 | BSD-2-clause,BSD-2-clause and MIT-CMU,BSD-2.2-clause,BSD-3-Clause-Attribution,BSD-3-Clause-Attribution and IBM-as-is,BSD-3-Clause-Attribu… |
| `libsasl2-modules-db` | 2.1.28+dfsg1-5ubuntu3.1 | cyrus-sasl2 | BSD-2-clause,BSD-2-clause and MIT-CMU,BSD-2.2-clause,BSD-3-Clause-Attribution,BSD-3-Clause-Attribution and IBM-as-is,BSD-3-Clause-Attribu… |
| `libseccomp2` | 2.5.5-1ubuntu3 | libseccomp | LGPL-2.1 |
| `libselinux1` | 3.5-2ubuntu2 | libselinux | GPL-2,public-domain |
| `libsemanage-common` | 3.5-1build5 | libsemanage | GPL-2,LGPL-2.1+ |
| `libsemanage2` | 3.5-1build5 | libsemanage | GPL-2,LGPL-2.1+ |
| `libsepol2` | 3.5-2build1 | libsepol | GPL-2,GPL-2+,LGPL-2.1+,Zlib |
| `libsmartcols1` | 2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `libsqlite3-0` | 3.45.1-1ubuntu2.8 | sqlite3 | GPL-2+,public-domain |
| `libss2` | 1.47.0-2.4~exp1ubuntu4.1 | e2fsprogs | Apache-2,BSD-3-Clause,GPL or MIT-US-export,GPL-2,GPL-2+ with Texinfo exception,ISC,Kazlib,LGPL-2,Latex2e |
| `libssh-4` | 0.10.6-2ubuntu0.5 | libssh | BSD-2-clause,BSD-3-clause,LGPL-2.1,LGPL-2.1+~OpenSSL,LGPL-2.1+~OpenSSL or BSD-2-clause or BSD-3-clause,public-domain |
| `libssl3t64` | 3.0.13-0ubuntu3.16 | openssl | Apache-2.0,Artistic,Artistic or GPL-1+,GPL-1+ |
| `libstdc++6` | 14-20240412-0ubuntu1 | gcc-14 | 이미지 안 copyright 파일 참조 |
| `libsystemd-shared` | 255.4-1ubuntu8.17 | systemd | CC0-1.0,Expat,GPL-2 with Linux-syscall-note exception,GPL-2+,LGPL-2.1+,public-domain |
| `libsystemd0` | 255.4-1ubuntu8.17 | systemd | CC0-1.0,Expat,GPL-2 with Linux-syscall-note exception,GPL-2+,LGPL-2.1+,public-domain |
| `libtasn1-6` | 4.19.0-3build1 | libtasn1-6 | 이미지 안 copyright 파일 참조 |
| `libtinfo6` | 6.4+20240113-1ubuntu2 | ncurses | BSD-3-clause,MIT/X11,X11 |
| `libtirpc-common` | 1.3.4+ds-1.1build1 | libtirpc | BSD-2-Clause,BSD-3-Clause,BSD-4-Clause,GPL-2,LGPL-2.1+,PERMISSIVE,__AUTO_PERMISSIVE__ |
| `libtirpc3t64` | 1.3.4+ds-1.1build1 | libtirpc | BSD-2-Clause,BSD-3-Clause,BSD-4-Clause,GPL-2,LGPL-2.1+,PERMISSIVE,__AUTO_PERMISSIVE__ |
| `libudev1` | 255.4-1ubuntu8.17 | systemd | CC0-1.0,Expat,GPL-2 with Linux-syscall-note exception,GPL-2+,LGPL-2.1+,public-domain |
| `libunistring5` | 1.1-2build1 | libunistring | FreeSoftware,GFDL-NIV-1.2+,GPL-2+,GPL-2+ with distribution exception,GPL-2+ with distribution exception, Expat and GPL-2+,GPL-3+,GPL-3+ o… |
| `liburcu8t64` | 0.14.0-3.1build1 | liburcu | BSD-2-clause,Expat,FSFAP,GPL-2,GPL-2 with Autoconf-data exception,GPL-2+,GPL-2+ with Autoconf-2.0~Archive exception,GPL-3+,GPL-3+ with Au… |
| `libuuid1` | 2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `libuv1t64` | 1.48.0-1.1build1 | libuv1 | Apache-2.0,BSD-2-clause,CC-BY-4.0,Expat,GPL3+ with autoconf exception,ISC |
| `libwrap0` | 7.6.q-33 | tcp-wrappers | BSD-3-clause,SSH,TCP-wrappers |
| `libxml2` | 2.9.14+dfsg-1.3ubuntu3.10 | libxml2 | ISC,MIT-1 |
| `libxmlsec1t64` | 1.2.39-5build2 | xmlsec1 | 이미지 안 copyright 파일 참조 |
| `libxmlsec1t64-openssl` | 1.2.39-5build2 | xmlsec1 | 이미지 안 copyright 파일 참조 |
| `libxslt1.1` | 1.1.39-0exp1ubuntu0.24.04.3 | libxslt | 이미지 안 copyright 파일 참조 |
| `libxtables12` | 1.8.10-3ubuntu2 | iptables | Artistic,GPL-2,GPL-2+,custom |
| `libxxhash0` | 0.8.2-2build1 | xxhash | BSD-2-clause,BSD-2-clause or GPL-2+,GPL-2+ |
| `libyaml-0-2` | 0.2.5-1build1 | libyaml | Expat,permissive |
| `libzstd1` | 1.5.5+dfsg2-2build1 | libzstd | BSD-3-clause,BSD-3-clause or GPL-2,Expat,GPL-2,zlib |
| `linux-base` | 4.5ubuntu9+24.04.2 | linux-base | 이미지 안 copyright 파일 참조 |
| `linux-image-6.8.0-146-generic` | 6.8.0-146.146 | linux-signed | 이미지 안 copyright 파일 참조 |
| `linux-image-virtual` | 6.8.0-146.146 | linux-meta | 이미지 안 copyright 파일 참조 |
| `linux-modules-6.8.0-146-generic` | 6.8.0-146.146 | linux | 이미지 안 copyright 파일 참조 |
| `login` | 1:4.13+dfsg1-4ubuntu3 | shadow | BSD-3-clause,GPL-1,GPL-2+,public-domain |
| `logrotate` | 3.21.0-2build1 | logrotate | BSD-3-Clause,GPL-2,GPL-3+ |
| `logsave` | 1.47.0-2.4~exp1ubuntu4.1 | e2fsprogs | Apache-2,BSD-3-Clause,GPL or MIT-US-export,GPL-2,GPL-2+ with Texinfo exception,ISC,Kazlib,LGPL-2,Latex2e |
| `lsb-release` | 12.0-2 | lsb-release-minimal | ISC |
| `lsof` | 4.95.0-1build3 | lsof | BSD-4-clause,GPL-2+,LGPL-2+,Purdue,sendmail |
| `mawk` | 1.3.4.20240123-1build1 | mawk | CC-BY-3.0,GPL-2.0-only,X11 |
| `media-types` | 10.1.0 | media-types | ad-hoc |
| `mokutil` | 0.6.0-2build3 | mokutil | GPL-3+ with OpenSSL exception |
| `mount` | 2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `nano` | 7.2-2ubuntu0.2 | nano | GFDL-NIV+,GFDL-NIV+ or GPL-3+,GPL-3+ |
| `ncurses-base` | 6.4+20240113-1ubuntu2 | ncurses | BSD-3-clause,MIT/X11,X11 |
| `ncurses-bin` | 6.4+20240113-1ubuntu2 | ncurses | BSD-3-clause,MIT/X11,X11 |
| `netbase` | 6.4 | netbase | GPL-2 |
| `netplan-generator` | 1.1.2-8ubuntu1~24.04.3 | netplan.io | GPL-3 |
| `netplan.io` | 1.1.2-8ubuntu1~24.04.3 | netplan.io | GPL-3 |
| `open-vm-tools` | 2:13.0.10-0ubuntu0.24.04.1 | open-vm-tools | BSD-3,GPL-2,GPL-2+,ISC-ibm-and-ibm-dhcp,LGPL-2.1,xfree86-1.0 |
| `openssh-client` | 1:9.6p1-3ubuntu13.19 | openssh | BSD-2-clause,BSD-3-clause,Expat-with-advertising-restriction,Mazieres-BSD-style,OpenSSH,Powell-BSD-style,public-domain |
| `openssh-server` | 1:9.6p1-3ubuntu13.19 | openssh | BSD-2-clause,BSD-3-clause,Expat-with-advertising-restriction,Mazieres-BSD-style,OpenSSH,Powell-BSD-style,public-domain |
| `openssh-sftp-server` | 1:9.6p1-3ubuntu13.19 | openssh | BSD-2-clause,BSD-3-clause,Expat-with-advertising-restriction,Mazieres-BSD-style,OpenSSH,Powell-BSD-style,public-domain |
| `openssl` | 3.0.13-0ubuntu3.16 | openssl | Apache-2.0,Artistic,Artistic or GPL-1+,GPL-1+ |
| `passwd` | 1:4.13+dfsg1-4ubuntu3 | shadow | BSD-3-clause,GPL-1,GPL-2+,public-domain |
| `pci.ids` | 0.0~2024.03.31-1ubuntu0.1 | pci.ids | BSD-3-clause,GPL-2+,GPL-2+ or BSD-3-clause |
| `pciutils` | 1:3.10.0-2build1 | pciutils | GPL-2+ |
| `perl-base` | 5.38.2-3.2build2 | perl | Artistic,Artistic or GPL-1+ or Artistic-dist,Artistic-2,Artistic-dist,BSD-3-clause,BSD-3-clause-GENERIC,BSD-3-clause-with-weird-numbering… |
| `procps` | 2:4.0.4-4ubuntu3 | procps | GPL-2.0+,LGPL-2.0+,LGPL-2.1+ |
| `python-apt-common` | 2.7.7ubuntu5.3 | python-apt | GPL-2+,Permissive |
| `python3` | 3.12.3-0ubuntu2.1 | python3-defaults | 이미지 안 copyright 파일 참조 |
| `python3-apt` | 2.7.7ubuntu5.3 | python-apt | GPL-2+,Permissive |
| `python3-cffi-backend` | 1.16.0-2build1 | python-cffi | Expat |
| `python3-minimal` | 3.12.3-0ubuntu2.1 | python3-defaults | 이미지 안 copyright 파일 참조 |
| `python3-netplan` | 1.1.2-8ubuntu1~24.04.3 | netplan.io | GPL-3 |
| `python3-pip` | 24.0+dfsg-1ubuntu1.3 | python-pip | Apache-2.0,Apache-2.0 OR BSD-2,BSD-2,BSD-3,Expat,ISC,LGPL-2.1+,MPL-2,Python |
| `python3-pip-whl` | 24.0+dfsg-1ubuntu1.3 | python-pip | Apache-2.0,Apache-2.0 OR BSD-2,BSD-2,BSD-3,Expat,ISC,LGPL-2.1+,MPL-2,Python |
| `python3-pkg-resources` | 68.1.2-2ubuntu1.2 | setuptools | Apache-2.0,BSD-3-clause |
| `python3-setuptools` | 68.1.2-2ubuntu1.2 | setuptools | Apache-2.0,BSD-3-clause |
| `python3-setuptools-whl` | 68.1.2-2ubuntu1.2 | setuptools | Apache-2.0,BSD-3-clause |
| `python3-venv` | 3.12.3-0ubuntu2.1 | python3-defaults | 이미지 안 copyright 파일 참조 |
| `python3-wheel` | 0.42.0-2 | wheel | Apache-2.0,Apache-2.0 or BSD-2-Clause,BSD-2-Clause,Expat,GPL-3 |
| `python3-yaml` | 6.0.1-2build2 | pyyaml | 이미지 안 copyright 파일 참조 |
| `python3.12` | 3.12.3-1ubuntu0.17 | python3.12 | PSF-2.0(이미지 안 copyright 파일 참조) |
| `python3.12-minimal` | 3.12.3-1ubuntu0.17 | python3.12 | PSF-2.0(이미지 안 copyright 파일 참조) |
| `python3.12-venv` | 3.12.3-1ubuntu0.17 | python3.12 | PSF-2.0(이미지 안 copyright 파일 참조) |
| `readline-common` | 8.2-4build1 | readline | GFDL-NIV-1.3+,GPL-2+,GPL-3,GPL-3+,ISC-no-attribution |
| `sbsigntool` | 0.9.4-3.1ubuntu7 | sbsigntool | CC0,GPL-3+,GPL-3+ with OpenSSL exception,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT |
| `sed` | 4.9-2build1 | sed | BSD-4-clause-UC,BSL-1,GFDL-NIV-1.3+,GPL-3+,GPL-3+ and ISC,ISC,X11,pcre |
| `sensible-utils` | 0.0.22 | sensible-utils | All-permissive,BSD-2-clause,GPL-2+,configure,installsh |
| `shim-signed` | 1.58+15.8-0ubuntu1 | shim-signed | BSD-2-Clause |
| `sqlite3` | 3.45.1-1ubuntu2.8 | sqlite3 | GPL-2+,public-domain |
| `sudo` | 1.9.15p5-3ubuntu5.24.04.4 | sudo | BSD-2-Clause,BSD-3-Clause,GPL-2+,ISC,Zlib,other,public-domain |
| `systemd` | 255.4-1ubuntu8.17 | systemd | CC0-1.0,Expat,GPL-2 with Linux-syscall-note exception,GPL-2+,LGPL-2.1+,public-domain |
| `systemd-dev` | 255.4-1ubuntu8.17 | systemd | CC0-1.0,Expat,GPL-2 with Linux-syscall-note exception,GPL-2+,LGPL-2.1+,public-domain |
| `systemd-resolved` | 255.4-1ubuntu8.17 | systemd | CC0-1.0,Expat,GPL-2 with Linux-syscall-note exception,GPL-2+,LGPL-2.1+,public-domain |
| `systemd-sysv` | 255.4-1ubuntu8.17 | systemd | CC0-1.0,Expat,GPL-2 with Linux-syscall-note exception,GPL-2+,LGPL-2.1+,public-domain |
| `sysvinit-utils` | 3.08-6ubuntu3 | sysvinit | GPL-2.0,GPL-2.0+,GPL-3.0,LGPL-2.1+ |
| `tar` | 1.35+dfsg-3build1 | tar | GPL-2+,GPL-3+,GPL-3+ with Bison exception,LGPL-2.1+,LGPL-3+ |
| `tcpdump` | 4.99.4-3ubuntu4.24.04.1 | tcpdump | 이미지 안 copyright 파일 참조 |
| `tzdata` | 2026c-0ubuntu0.24.04.1 | tzdata | ICU,public-domain |
| `tzdata-legacy` | 2026c-0ubuntu0.24.04.1 | tzdata | ICU,public-domain |
| `ubuntu-keyring` | 2023.11.28.1 | ubuntu-keyring | 이미지 안 copyright 파일 참조 |
| `ucf` | 3.0043+nmu1 | ucf | GPL-2 |
| `udev` | 255.4-1ubuntu8.17 | systemd | CC0-1.0,Expat,GPL-2 with Linux-syscall-note exception,GPL-2+,LGPL-2.1+,public-domain |
| `ufw` | 0.36.2-6 | ufw | BSD-3-clause,GPL-3 |
| `util-linux` | 2.39.3-9ubuntu6.6 | util-linux | BSD-3-clause,BSD-4-clause,BSLA,GPL-2,GPL-2+,GPL-3+,LGPL,LGPL-2+,LGPL-2.1+,LGPL-3+,MIT,public-domain |
| `vim-common` | 2:9.1.0016-1ubuntu7.20 | vim | Apache,Apache or Expat,Artistic-1,BSD-2-clause,BSD-3-clause,Compaq,EDL-1,Expat,Expat or GPL-2,Expat or Vim,GPL-1+,GPL-1+ or Artistic-1,GP… |
| `vim-tiny` | 2:9.1.0016-1ubuntu7.20 | vim | Apache,Apache or Expat,Artistic-1,BSD-2-clause,BSD-3-clause,Compaq,EDL-1,Expat,Expat or GPL-2,Expat or Vim,GPL-1+,GPL-1+ or Artistic-1,GP… |
| `xfsprogs` | 6.6.0-1ubuntu2.1 | xfsprogs | GPL-2,GPL-3+ with autoconf exception,LGPL-2.1 |
| `zlib1g` | 1:1.3.dfsg-3.1ubuntu2 | zlib | Zlib |
