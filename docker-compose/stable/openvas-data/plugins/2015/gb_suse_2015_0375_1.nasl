# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850636");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-02-26 05:39:14 +0100 (Thu, 26 Feb 2015)");
  script_cve_id("CVE-2014-8143", "CVE-2015-0240");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for samba (openSUSE-SU-2015:0375-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"samba was updated to fix two security issues.

  These security issues were fixed:

  - CVE-2015-0240: Ensure we don't call talloc_free on an uninitialized
  pointer (bnc#917376).

  - CVE-2014-8143: Samba 4.0.x before 4.0.24, 4.1.x before 4.1.16, and 4.2.x
  before 4.2rc4, when an Active Directory Domain Controller (AD DC) is
  configured, allowed remote authenticated users to set the LDB
  userAccountControl UF_SERVER_TRUST_ACCOUNT bit, and consequently gain
  privileges, by leveraging delegation of authority for user-account or
  computer-account creation (bnc#914279).

  Several non-security issues were fixed, please refer to the changes file.");

  script_tag(name:"affected", value:"samba on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:0375-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-atsvc-devel", rpm:"libdcerpc-atsvc-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-atsvc0", rpm:"libdcerpc-atsvc0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-atsvc0-debuginfo", rpm:"libdcerpc-atsvc0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0", rpm:"libdcerpc-binding0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-debuginfo", rpm:"libdcerpc-binding0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-devel", rpm:"libdcerpc-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr-devel", rpm:"libdcerpc-samr-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0", rpm:"libdcerpc-samr0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0-debuginfo", rpm:"libdcerpc-samr0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0", rpm:"libdcerpc0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-debuginfo", rpm:"libdcerpc0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec-devel", rpm:"libgensec-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec0", rpm:"libgensec0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec0-debuginfo", rpm:"libgensec0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-devel", rpm:"libndr-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac-devel", rpm:"libndr-krb5pac-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0", rpm:"libndr-krb5pac0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-debuginfo", rpm:"libndr-krb5pac0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt-devel", rpm:"libndr-nbt-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0", rpm:"libndr-nbt0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-debuginfo", rpm:"libndr-nbt0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard-devel", rpm:"libndr-standard-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0", rpm:"libndr-standard0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-debuginfo", rpm:"libndr-standard0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0", rpm:"libndr0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-debuginfo", rpm:"libndr0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-debuginfo", rpm:"libnetapi0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpdb-devel", rpm:"libpdb-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpdb0", rpm:"libpdb0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpdb0-debuginfo", rpm:"libpdb0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libregistry-devel", rpm:"libregistry-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libregistry0", rpm:"libregistry0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libregistry0-debuginfo", rpm:"libregistry0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials-devel", rpm:"libsamba-credentials-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0", rpm:"libsamba-credentials0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-debuginfo", rpm:"libsamba-credentials0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig-devel", rpm:"libsamba-hostconfig-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0", rpm:"libsamba-hostconfig0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-debuginfo", rpm:"libsamba-hostconfig0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0", rpm:"libsamba-policy0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-debuginfo", rpm:"libsamba-policy0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util-devel", rpm:"libsamba-util-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0", rpm:"libsamba-util0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-debuginfo", rpm:"libsamba-util0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb-devel", rpm:"libsamdb-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0", rpm:"libsamdb0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-debuginfo", rpm:"libsamdb0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw-devel", rpm:"libsmbclient-raw-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw0", rpm:"libsmbclient-raw0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw0-debuginfo", rpm:"libsmbclient-raw0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo", rpm:"libsmbclient0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf-devel", rpm:"libsmbconf-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0", rpm:"libsmbconf0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-debuginfo", rpm:"libsmbconf0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap-devel", rpm:"libsmbldap-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0", rpm:"libsmbldap0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0-debuginfo", rpm:"libsmbldap0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes0-debuginfo", rpm:"libsmbsharemodes0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util-devel", rpm:"libtevent-util-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0", rpm:"libtevent-util0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-debuginfo", rpm:"libtevent-util0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo", rpm:"libwbclient0-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-core-devel", rpm:"samba-core-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-pidl", rpm:"samba-pidl~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python-debuginfo", rpm:"samba-python-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test-debuginfo", rpm:"samba-test-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test-devel", rpm:"samba-test-devel~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-atsvc0-32bit", rpm:"libdcerpc-atsvc0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-atsvc0-debuginfo-32bit", rpm:"libdcerpc-atsvc0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit", rpm:"libdcerpc-binding0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-debuginfo-32bit", rpm:"libdcerpc-binding0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0-32bit", rpm:"libdcerpc-samr0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0-debuginfo-32bit", rpm:"libdcerpc-samr0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit", rpm:"libdcerpc0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-debuginfo-32bit", rpm:"libdcerpc0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec0-32bit", rpm:"libgensec0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec0-debuginfo-32bit", rpm:"libgensec0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit", rpm:"libndr-krb5pac0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-debuginfo-32bit", rpm:"libndr-krb5pac0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit", rpm:"libndr-nbt0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-debuginfo-32bit", rpm:"libndr-nbt0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit", rpm:"libndr-standard0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-debuginfo-32bit", rpm:"libndr-standard0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit", rpm:"libndr0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-debuginfo-32bit", rpm:"libndr0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit", rpm:"libnetapi0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-debuginfo-32bit", rpm:"libnetapi0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpdb0-32bit", rpm:"libpdb0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpdb0-debuginfo-32bit", rpm:"libpdb0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libregistry0-32bit", rpm:"libregistry0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libregistry0-debuginfo-32bit", rpm:"libregistry0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit", rpm:"libsamba-credentials0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-debuginfo-32bit", rpm:"libsamba-credentials0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit", rpm:"libsamba-hostconfig0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-debuginfo-32bit", rpm:"libsamba-hostconfig0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-32bit", rpm:"libsamba-policy0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-debuginfo-32bit", rpm:"libsamba-policy0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit", rpm:"libsamba-util0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-debuginfo-32bit", rpm:"libsamba-util0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit", rpm:"libsamdb0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-debuginfo-32bit", rpm:"libsamdb0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw0-32bit", rpm:"libsmbclient-raw0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw0-debuginfo-32bit", rpm:"libsmbclient-raw0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-32bit", rpm:"libsmbclient0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo-32bit", rpm:"libsmbclient0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit", rpm:"libsmbconf0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-debuginfo-32bit", rpm:"libsmbconf0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0-32bit", rpm:"libsmbldap0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0-debuginfo-32bit", rpm:"libsmbldap0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit", rpm:"libtevent-util0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-debuginfo-32bit", rpm:"libtevent-util0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo-32bit", rpm:"libwbclient0-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-32bit", rpm:"samba-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo-32bit", rpm:"samba-client-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo-32bit", rpm:"samba-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo-32bit", rpm:"samba-libs-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo-32bit", rpm:"samba-winbind-debuginfo-32bit~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~4.1.17~3.30.1", rls:"openSUSE13.1"))) {
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
