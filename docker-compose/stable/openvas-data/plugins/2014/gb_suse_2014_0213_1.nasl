# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850567");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-02-11 10:40:12 +0530 (Tue, 11 Feb 2014)");
  script_cve_id("CVE-2013-1740", "CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479",
                "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1486", "CVE-2014-1487",
                "CVE-2014-1490", "CVE-2014-1491");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for Mozilla (openSUSE-SU-2014:0213-1)");

  script_tag(name:"affected", value:"Mozilla on openSUSE 11.4");

  script_tag(name:"insight", value:"Updates for mozilla-nss (3.15.4) MozillaFirefox (24.3.0esr)
  MozillaThunderbird (24.3.0) including fixes for the
  following issues:

  * MFSA 2014-01/CVE-2014-1477/CVE-2014-1478 Miscellaneous
  memory safety hazards (rv:27.0 / rv:24.3)

  * MFSA 2014-02/CVE-2014-1479 (bmo#911864) Clone protected
  content with XBL scopes

  * MFSA 2014-04/CVE-2014-1482 (bmo#943803) Incorrect use
  of discarded images by RasterImage

  * MFSA 2014-08/CVE-2014-1486 (bmo#942164) Use-after-free
  with imgRequestProxy and image processing

  * MFSA 2014-09/CVE-2014-1487 (bmo#947592) Cross-origin
  information leak through web workers

  * MFSA 2014-12/CVE-2014-1490/CVE-2014-1491 (bmo#934545,
  bmo#930874, bmo#930857) NSS ticket handling issues

  * MFSA 2014-13/CVE-2014-1481(bmo#936056) Inconsistent
  JavaScript handling of access to Window objects");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"openSUSE-SU", value:"2014:0213-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.3.0~99.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~24.3.0~99.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~24.3.0~99.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~24.3.0~99.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~24.3.0~99.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~24.3.0~99.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~24.3.0~99.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~24.3.0~99.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~24.3.0~85.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~24.3.0~85.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~24.3.0~85.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~24.3.0~85.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~24.3.0~85.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~24.3.0~85.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~24.3.0~85.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.6.0+24.3.0~85.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-x86", rpm:"libfreebl3-debuginfo-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-x86", rpm:"libfreebl3-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-x86", rpm:"libsoftokn3-debuginfo-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-x86", rpm:"libsoftokn3-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-x86", rpm:"mozilla-nss-certs-debuginfo-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-x86", rpm:"mozilla-nss-certs-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-x86", rpm:"mozilla-nss-debuginfo-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-x86", rpm:"mozilla-nss-sysinit-debuginfo-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-x86", rpm:"mozilla-nss-sysinit-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.15.4~78.1", rls:"openSUSE11.4"))) {
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
