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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0088.1");
  script_cve_id("CVE-2019-11727", "CVE-2019-11745", "CVE-2019-17006");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-19 16:59:00 +0000 (Fri, 19 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0088-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5|SLES12\.0SP4|SLES12\.0SP3|SLES12\.0SP2|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0088-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200088-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-nspr, mozilla-nss' package(s) announced via the SUSE-SU-2020:0088-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mozilla-nspr, mozilla-nss fixes the following issues:

mozilla-nss was updated to NSS 3.47.1:

Security issues fixed:
CVE-2019-17006: Added length checks for cryptographic primitives
 (bsc#1159819).

CVE-2019-11745: EncryptUpdate should use maxout, not block size
 (bsc#1158527).

CVE-2019-11727: Fixed vulnerability sign CertificateVerify with PKCS#1
 v1.5 signatures issue (bsc#1141322).

mozilla-nspr was updated to version 4.23:
Whitespace in C files was cleaned up and no longer uses tab characters
 for indenting.");

  script_tag(name:"affected", value:"'mozilla-nspr, mozilla-nss' package(s) on SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 7, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Desktop 12-SP4, SUSE Enterprise Storage 5, SUSE CaaS Platform 3.0, HPE Helion Openstack 8.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.23~19.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.23~19.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.23~19.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.23~19.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.23~19.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.23~19.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.23~19.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.23~19.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.23~19.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.23~19.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.23~19.12.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.23~19.12.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.23~19.12.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.23~19.12.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.23~19.12.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.23~19.12.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.23~19.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.23~19.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.23~19.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.23~19.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.23~19.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.23~19.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.23~19.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.23~19.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.23~19.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.23~19.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.23~19.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.47.1~58.34.1", rls:"SLES12.0SP1"))) {
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
