# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2545.1");
  script_cve_id("CVE-2019-11710", "CVE-2019-11714", "CVE-2019-11716", "CVE-2019-11718", "CVE-2019-11720", "CVE-2019-11721", "CVE-2019-11723", "CVE-2019-11724", "CVE-2019-11725", "CVE-2019-11727", "CVE-2019-11728", "CVE-2019-11733", "CVE-2019-11735", "CVE-2019-11736", "CVE-2019-11738", "CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11747", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750", "CVE-2019-11751", "CVE-2019-11752", "CVE-2019-11753", "CVE-2019-9811", "CVE-2019-9812");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:16 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-15 18:15:00 +0000 (Thu, 15 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2545-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2545-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192545-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2019:2545-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to 68.1 fixes the following issues:

Security issues fixed:
CVE-2019-9811: Fixed a sandbox escape via installation of malicious
 language pack. (bsc#1140868)

CVE-2019-9812: Fixed a sandbox escape through Firefox Sync. (bsc#1149294)

CVE-2019-11710: Fixed several memory safety bugs. (bsc#1140868)

CVE-2019-11714: Fixed a potentially exploitable crash in Necko.
 (bsc#1140868)

CVE-2019-11716: Fixed a sandbox bypass. (bsc#1140868)

CVE-2019-11718: Fixed inadequate sanitation in the Activity Stream
 component. (bsc#1140868)

CVE-2019-11720: Fixed a character encoding XSS vulnerability.
 (bsc#1140868)

CVE-2019-11721: Fixed a homograph domain spoofing issue through unicode
 latin 'kra' character. (bsc#1140868)

CVE-2019-11723: Fixed a cookie leakage during add-on fetching across
 private browsing boundaries. (bsc#1140868)

CVE-2019-11724: Fixed an outdated permission, granting access to retired
 site input.mozilla.org. (bsc#1140868)

CVE-2019-11725: Fixed a Safebrowsing bypass involving WebSockets.
 (bsc#1140868)

CVE-2019-11727: Fixed a vulnerability where it possible to force NSS to
 sign CertificateVerify with PKCS#1 v1.5 signatures when those are the
 only ones advertised by server in CertificateRequest in TLS 1.3.
 (bsc#1141322)

CVE-2019-11728: Fixed an improper handling of the Alt-Svc header that
 allowed remote port scans. (bsc#1140868)

CVE-2019-11733: Fixed an insufficient protection of stored passwords in
 'Saved Logins'. (bnc#1145665)

CVE-2019-11735: Fixed several memory safety bugs. (bnc#1149293)

CVE-2019-11736: Fixed a file manipulation and privilege escalation in
 Mozilla Maintenance Service. (bnc#1149292)

CVE-2019-11738: Fixed a content security policy bypass through
 hash-based sources in directives. (bnc#1149302)

CVE-2019-11740: Fixed several memory safety bugs. (bsc#1149299)

CVE-2019-11742: Fixed a same-origin policy violation involving SVG
 filters and canvas to steal cross-origin images. (bsc#1149303)

CVE-2019-11743: Fixed a timing side-channel attack on cross-origin
 information, utilizing unload event attributes. (bsc#1149298)

CVE-2019-11744: Fixed an XSS caused by breaking out of title and
 textarea elements using innerHTML. (bsc#1149304)

CVE-2019-11746: Fixed a use-after-free while manipulating video.
 (bsc#1149297)

CVE-2019-11752: Fixed a use-after-free while extracting a key value in
 IndexedDB. (bsc#1149296)

CVE-2019-11753: Fixed a privilege escalation with Mozilla Maintenance
 Service in custom Firefox installation location. (bsc#1149295)

Non-security issues fixed:
Latest update now also released for s390x. (bsc#1109465)

Fixed a segmentation fault on s390vsl082. (bsc#1117473)

Fixed a crash on SLES15 s390x. (bsc#1124525)

Fixed a segmentation fault. (bsc#1133810)");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Module for Desktop Applications 15.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.1.0~3.54.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~68~4.8.5", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~68.1.0~3.54.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~68.1.0~3.54.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.1.0~3.54.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~68.1.0~3.54.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~68.1.0~3.54.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.1.0~3.54.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~68~4.8.5", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~68.1.0~3.54.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~68.1.0~3.54.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~68.1.0~3.54.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.1.0~3.54.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~68.1.0~3.54.2", rls:"SLES15.0"))) {
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
