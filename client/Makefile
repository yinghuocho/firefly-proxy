VERSION := 0.4.8
SHORTVERSION := 0.4.8

.PHONY: windows package-windows linux package-linux darwin package-darwin clean

define fpm-debian-build
	echo "Running fpm-debian-build" && \
	PKG_ARCH=$1 && \
	VERSION=$2 && \
	WORKDIR=$$(mktemp -dt "$$(basename $$0).XXXXXXXXXX") && \
	INSTALLER_RESOURCES=./installer/linux && \
	DESC="A proxy software for censorship circumvention" && \
	\
	mkdir -p $$WORKDIR/usr/bin && \
	mkdir -p $$WORKDIR/usr/share/applications && \
	mkdir -p $$WORKDIR/usr/share/icons/hicolor/256x256/apps && \
	chmod -R 755 $$WORKDIR && \
	\
	cp $$INSTALLER_RESOURCES/firefly.desktop $$WORKDIR/usr/share/applications && \
	chmod 664 $$WORKDIR/usr/share/applications/firefly.desktop && \
	cp $$INSTALLER_RESOURCES/firefly_256.png $$WORKDIR/usr/share/icons/hicolor/256x256/apps/firefly.png && \
	chmod 664 $$WORKDIR/usr/share/icons/hicolor/256x256/apps/firefly.png && \
	\
	cp $3 $$WORKDIR/usr/bin/firefly-bin && \
	cp $$INSTALLER_RESOURCES/firefly.sh $$WORKDIR/usr/bin/firefly && \
	\
	chmod 664 $$WORKDIR/usr/bin/firefly-bin && \
	chmod 775 $$WORKDIR/usr/bin/firefly && \
	\
	fpm --depends "libappindicator3-1" --license BSD --description "$$DESC" --vendor yinghuocho --maintainer "yinghuocho <yinghuocho@gmail.com>" --url https://gofirefly.org/ -a $$PKG_ARCH -s dir -t deb -n firefly -v $$VERSION -C $$WORKDIR -f usr;
endef

windows:
	GOOS=windows GOARCH=386 go build -ldflags="-w -s -H windowsgui" -a -o firefly.exe

package-windows: windows
	sed "s/__VERSION__/${VERSION}/g" installer/windows/firefly.nsi > firefly-${VERSION}.nsi
	@echo "Please execute firefly-${VERSION}.nsi under windows"

linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -linkmode internal" -a -o firefly

linux32:
	GOOS=linux GOARCH=386 go build -ldflags="-w -s -linkmode internal" -a -o firefly32

package-linux: linux
	$(call fpm-debian-build,"amd64","${VERSION}","firefly")

package-linux32:
	$(call fpm-debian-build,"i386","${VERSION}","firefly32")

darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-w" -a -o firefly_darwin_amd64

package-darwin: darwin
	rm -rf Firefly.app
	cp -r installer/darwin/Firefly.app.template Firefly.app
	mkdir Firefly.app/Contents/MacOS
	cp -r firefly_darwin_amd64 Firefly.app/Contents/MacOS/firefly
	sed "s/__VERSION__/${VERSION}/g; s/__SHORTVERSION__/${SHORTVERSION}/g" installer/darwin/Firefly.app.template/Contents/Info.plist > Firefly.app/Contents/Info.plist
	sed "s/__VERSION__/${VERSION}/g" installer/darwin/firefly.dmg.json > installer/darwin/firefly-${VERSION}.dmg.json
	rm -rf firefly-${VERSION}.dmg
	appdmg --quiet installer/darwin/firefly-${VERSION}.dmg.json firefly-${VERSION}.dmg
	rm -rf installer/darwin/firefly-${VERSION}.dmg.json
	mv firefly-${VERSION}.dmg firefly-${VERSION}.dmg.zlib
	hdiutil convert -quiet -format UDBZ -o firefly-${VERSION}.dmg firefly-${VERSION}.dmg.zlib
	rm firefly-${VERSION}.dmg.zlib

clean:
	rm -rf firefly firefly.exe firefly_darwin_amd64 Firefly.app firefly-${VERSION}.dmg firefly-${VERSION}.nsi firefly-${VERSION}-install.exe firefly_${VERSION}_amd64.deb update_*
