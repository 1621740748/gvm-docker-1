# Copyright (C) 2013 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850461");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:55 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0791", "CVE-2013-0792",
                "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796",
                "CVE-2013-0800", "CVE-2013-1620");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for Mozilla Firefox and others (openSUSE-SU-2013:0630-1)");

  script_tag(name:"affected", value:"Mozilla Firefox and others on openSUSE 12.2, openSUSE 12.1");

  script_tag(name:"insight", value:"The Mozilla suite received security and bugfix updates:

  Mozilla Firefox was updated to version 20.0. Mozilla
  Thunderbird was updated to version 17.0.5. Mozilla
  Seamonkey was updated to version 17.0.5. Mozilla XULRunner
  was updated to version 17.0.5. mozilla-nss was updated to
  version 3.14.3. mozilla-nspr was updated to version 4.9.6.

  mozilla-nspr was updated to version 4.9.6:

  * aarch64 support

  * added PL_SizeOfArenaPoolExcludingPool function
  (bmo#807883)

  * Auto detect android api version for x86 (bmo#782214)

  * Initialize Windows CRITICAL_SECTIONs without debug info
  and with nonzero spin count (bmo#812085) Previous update
  to version 4.9.5

  * bmo#634793: define NSPR's exact-width integer types
  PRInt{N} and PRUint{N} types to match the <stdint.h&>
  exact-width integer types int{N}_t and uint{N}_t.

  * bmo#782815: passing 'int *' to parameter of type
  'unsigned int *' in setsockopt().

  * bmo#822932: Port bmo#802527 (NDK r8b support for x86) to
  NSPR.

  * bmo#824742: NSPR shouldn't require librt on Android.

  * bmo#831793: data race on lib-&>refCount in
  PR_UnloadLibrary.

  mozilla-nss was updated to version 3.14.3:

  * disable tests with expired certificates

  * add SEC_PKCS7VerifyDetachedSignatureAtTime using patch
  from mozilla tree to fulfill Firefox 21 requirements

  * No new major functionality is introduced in this release.
  This release is a patch release to address CVE-2013-1620
  (bmo#822365)

  * 'certutil -a' was not correctly producing ASCII output as
  requested. (bmo#840714)

  * NSS 3.14.2 broke compilation with older versions of
  sqlite that lacked the SQLITE_FCNTL_TEMPFILENAME file
  control. NSS 3.14.3 now properly compiles when used with
  older versions of sqlite (bmo#837799) - remove
  system-sqlite.patch

  * add arm aarch64 support

  * added system-sqlite.patch (bmo#837799)

  * do not depend on latest sqlite just for a #define

  * enable system sqlite usage again

  * update to 3.14.2

  * required for Firefox &>= 20

  * removed obsolete nssckbi update patch

  * MFSA 2013-40/CVE-2013-0791 (bmo#629816) Out-of-bounds
  array read in CERT_DecodeCertPackage

  * disable system sqlite usage since we depend on 3.7.15
  which is not provided in any openSUSE distribution

  * add nss-sqlitename.patch to avoid any name clash

  Changes in MozillaFirefox:

  - update to Firefox 20.0 (bnc#813026)

  * requires NSPR 4.9.5 and NSS 3.14.3

  * MFSA 2013-30/CVE-2013-0788/CVE-2013-0789 Miscellaneous
  memory safety hazards

  * MFSA 2013-31/CVE-2013-0800 (bmo#825721) Out-of-bounds");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"openSUSE-SU", value:"2013:0630-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox and others'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE12\.2|openSUSE12\.1)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.2") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~20.0~2.41.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~20.0~2.41.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~20.0~2.41.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~20.0~2.41.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~20.0~2.41.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~20.0~2.41.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~20.0~2.41.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~20.0~2.41.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel-debuginfo", rpm:"MozillaThunderbird-devel-debuginfo~17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.5.1+17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail-debuginfo", rpm:"enigmail-debuginfo~1.5.1+17.0.5~49.39.3", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js", rpm:"mozilla-js~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js-debuginfo", rpm:"mozilla-js-debuginfo~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.9.6~1.12.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.9.6~1.12.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.9.6~1.12.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.9.6~1.12.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-buildsymbols", rpm:"xulrunner-buildsymbols~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-debugsource", rpm:"xulrunner-debugsource~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel-debuginfo", rpm:"xulrunner-devel-debuginfo~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js-32bit", rpm:"mozilla-js-32bit~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js-debuginfo-32bit", rpm:"mozilla-js-debuginfo-32bit~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.9.6~1.12.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.9.6~1.12.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.14.3~2.19.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-32bit", rpm:"xulrunner-32bit~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-debuginfo-32bit", rpm:"xulrunner-debuginfo-32bit~17.0.5~2.38.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~20.0~2.70.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~20.0~2.70.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~20.0~2.70.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~20.0~2.70.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~20.0~2.70.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~20.0~2.70.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~20.0~2.70.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~20.0~2.70.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel-debuginfo", rpm:"MozillaThunderbird-devel-debuginfo~17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.5.1+17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail-debuginfo", rpm:"enigmail-debuginfo~1.5.1+17.0.5~33.59.3", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js", rpm:"mozilla-js~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js-debuginfo", rpm:"mozilla-js-debuginfo~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.9.6~3.15.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.9.6~3.15.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.9.6~3.15.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.9.6~3.15.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.17~2.61.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.17~2.61.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.17~2.61.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.17~2.61.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.17~2.61.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.17~2.61.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.17~2.61.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.17~2.61.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-buildsymbols", rpm:"xulrunner-buildsymbols~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-debugsource", rpm:"xulrunner-debugsource~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel-debuginfo", rpm:"xulrunner-devel-debuginfo~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js-32bit", rpm:"mozilla-js-32bit~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js-debuginfo-32bit", rpm:"mozilla-js-debuginfo-32bit~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.9.6~3.15.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.9.6~3.15.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-32bit", rpm:"xulrunner-32bit~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-debuginfo-32bit", rpm:"xulrunner-debuginfo-32bit~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-x86", rpm:"libfreebl3-debuginfo-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-x86", rpm:"libfreebl3-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-x86", rpm:"libsoftokn3-debuginfo-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-x86", rpm:"libsoftokn3-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js-debuginfo-x86", rpm:"mozilla-js-debuginfo-x86~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js-x86", rpm:"mozilla-js-x86~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-x86", rpm:"mozilla-nspr-debuginfo-x86~4.9.6~3.15.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-x86", rpm:"mozilla-nspr-x86~4.9.6~3.15.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-x86", rpm:"mozilla-nss-certs-debuginfo-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-x86", rpm:"mozilla-nss-certs-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-x86", rpm:"mozilla-nss-debuginfo-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-x86", rpm:"mozilla-nss-sysinit-debuginfo-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-x86", rpm:"mozilla-nss-sysinit-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.14.3~9.29.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-debuginfo-x86", rpm:"xulrunner-debuginfo-x86~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-x86", rpm:"xulrunner-x86~17.0.5~2.65.2", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
