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
  script_oid("1.3.6.1.4.1.25623.1.0.122357");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"creation_date", value:"2015-10-06 14:17:28 +0300 (Tue, 06 Oct 2015)");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_name("Oracle Linux Local Check: ELSA-2010-0430");
  script_tag(name:"insight", value:"ELSA-2010-0430 - postgresql84 security update. Please see the references for more insight.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2010-0430");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2010-0430.html");
  script_cve_id("CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1975");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");
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
  if ((res = isrpmvuln(pkg:"postgresql84", rpm:"postgresql84~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-contrib", rpm:"postgresql84-contrib~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-devel", rpm:"postgresql84-devel~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-docs", rpm:"postgresql84-docs~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-libs", rpm:"postgresql84-libs~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-plperl", rpm:"postgresql84-plperl~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-plpython", rpm:"postgresql84-plpython~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-pltcl", rpm:"postgresql84-pltcl~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-python", rpm:"postgresql84-python~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-server", rpm:"postgresql84-server~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-tcl", rpm:"postgresql84-tcl~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"postgresql84-test", rpm:"postgresql84-test~8.4.4~1.el5_5.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

