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
  script_oid("1.3.6.1.4.1.25623.1.0.850551");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-12-10 13:21:24 +0530 (Tue, 10 Dec 2013)");
  script_cve_id("CVE-2013-4124");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("openSUSE: Security Advisory for update (openSUSE-SU-2013:1349-1)");

  script_tag(name:"affected", value:"update on openSUSE 12.3");

  script_tag(name:"insight", value:"This update of samba fixed the following issues:

  - The pam_winbind require_membership_of option allows for a
  list of SID, but currently only provides buffer space for
  ~20  (bnc#806501).

  - Samba 3.0.x to 4.0.7 are affected by a denial of service
  attack on authenticated or guest connections
  CVE-2013-4124  (bnc#829969).

  - PIDL: fix parsing linemarkers in preprocessor output
  (bso#9636).

  - build:autoconf: fix output of syslog-facility check
  (bso#9983).

  - libreplace: add a missing 'eval' to the
  AC_VERIFY_C_PROTOTYPE macro.

  - Remove ldapsmb from the main spec file.

  - Don't bzip2 the main tar ball, use the upstream gzipped
  one instead.

  - Fix crash bug during Win8 sync  (bso#9822).

  - Check for system libtevent and link dbwrap_tool and
  dbwrap_torture against it  (bso#9881).

  - errno gets overwritten in call to check_parent_exists()
  (bso#9927).

  - Fix a bug of drvupgrade of smbcontrol  (bso#9941).

  - Document idmap_ad rfc2307 attribute requirements
  (bso#9880)  (bnc#820531).

  - Don't package the SWAT man page while its build is
  disabled  (bnc#816647).

  - Don't install the tdb utilities man pages on post-12.1
  systems  (bnc#823549).

  - Fix libreplace license ambiguity  (bso#8997)
  (bnc#765270).

  - s3-docs: Remove 'experimental' label on 'max
  protocol=SMB2' parameter  (bso#9688).

  - Remove the compound_related_in_progress state from the
  smb2 global state  (bso#9722).

  - Makefile: Don't know how to make LIBNDR_PREG_OBJ
  (bso#9868).

  - Fix is_printer_published GUID retrieval  (bso#9900)
  (bnc#798856).

  - Fix 'map untrusted to domain' with NTLMv2  (bso#9817)
  (bnc#817919).

  - Don't modify the pidfile name when a custom config file
  path is used  (bnc#812929).

  - Add extra attributes for AD printer publishing
  (bso#9378)  (bnc#798856).

  - Fix vfs_catia module  (bso#9701)  (bnc#824833). systems
  (bnc#804822)  (bnc#821889).

  - Fix AD printer publishing  (bso#9378)  (bnc#798856).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"openSUSE-SU", value:"2013:1349-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.3");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.3") {
  if(!isnull(res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-debuginfo", rpm:"libnetapi0-debuginfo~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo", rpm:"libsmbclient0-debuginfo~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes0-debuginfo", rpm:"libsmbsharemodes0-debuginfo~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo", rpm:"libwbclient0-debuginfo~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb-printing", rpm:"samba-krb-printing~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb-printing-debuginfo", rpm:"samba-krb-printing-debuginfo~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-32bit", rpm:"libsmbclient0-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo-32bit", rpm:"libsmbclient0-debuginfo-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo-32bit", rpm:"libwbclient0-debuginfo-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-32bit", rpm:"samba-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo-32bit", rpm:"samba-client-debuginfo-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo-32bit", rpm:"samba-debuginfo-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo-32bit", rpm:"samba-winbind-debuginfo-32bit~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.6.12~59.9.1", rls:"openSUSE12.3"))) {
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
