###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Linux Local Check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (C) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123385");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"creation_date", value:"2015-10-06 14:03:06 +0300 (Tue, 06 Oct 2015)");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_name("Oracle Linux Local Check: ELSA-2014-0866");
  script_tag(name:"insight", value:"ELSA-2014-0866 - samba and samba3x security update. Please see the references for more insight.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2014-0866");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2014-0866.html");
  script_cve_id("CVE-2014-0244", "CVE-2014-3493");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux(5|6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Oracle Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"samba3x", rpm:"samba3x~3.6.6~0.140.el5_10", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-client", rpm:"samba3x-client~3.6.6~0.140.el5_10", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-common", rpm:"samba3x-common~3.6.6~0.140.el5_10", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-doc", rpm:"samba3x-doc~3.6.6~0.140.el5_10", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-domainjoin-gui", rpm:"samba3x-domainjoin-gui~3.6.6~0.140.el5_10", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-swat", rpm:"samba3x-swat~3.6.6~0.140.el5_10", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-winbind", rpm:"samba3x-winbind~3.6.6~0.140.el5_10", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-winbind-devel", rpm:"samba3x-winbind-devel~3.6.6~0.140.el5_10", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-domainjoin-gui", rpm:"samba-domainjoin-gui~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-winbind-devel", rpm:"samba-winbind-devel~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~3.6.9~169.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

