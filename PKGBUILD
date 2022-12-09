# Maintainer: kpcyrd <kpcyrd[at]archlinux[dot]org>

pkgname=sh4d0wup
pkgver=0.0.0
pkgrel=1
pkgdesc="Signing-key abuse and update exploitation framework"
url='https://github.com/kpcyrd/sh4d0wup'
arch=('x86_64')
license=('GPL-3.0-or-later')
depends=('podman' 'openssl' 'shared-mime-info' 'xz' 'libzstd.so')
checkdepends=('sequoia-sqv')
makedepends=('cargo' 'clang')

build() {
  cd ..
  cargo build --release --locked
}

package() {
  cd ..
  install -Dm 755 -t "${pkgdir}/usr/bin" \
    target/release/sh4d0wup

  # install completions
  install -d "${pkgdir}/usr/share/bash-completion/completions" \
             "${pkgdir}/usr/share/zsh/site-functions" \
             "${pkgdir}/usr/share/fish/vendor_completions.d"
  "${pkgdir}/usr/bin/${pkgname}" completions bash > "${pkgdir}/usr/share/bash-completion/completions/${pkgname}"
  "${pkgdir}/usr/bin/${pkgname}" completions zsh > "${pkgdir}/usr/share/zsh/site-functions/_${pkgname}"
  "${pkgdir}/usr/bin/${pkgname}" completions fish > "${pkgdir}/usr/share/fish/vendor_completions.d/${pkgname}.fish"
}

# vim: ts=2 sw=2 et:
