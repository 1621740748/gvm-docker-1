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
  script_oid("1.3.6.1.4.1.25623.1.0.122012");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"creation_date", value:"2015-10-06 14:11:40 +0300 (Tue, 06 Oct 2015)");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_name("Oracle Linux Local Check: ELSA-2012-0019");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2012-0019");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2012-0019.html");
  script_cve_id("CVE-2011-4566", "CVE-2011-4885");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-cli", rpm:"php53-cli~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-common", rpm:"php53-common~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-devel", rpm:"php53-devel~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-imap", rpm:"php53-imap~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-process", rpm:"php53-process~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-xml", rpm:"php53-xml~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.3~1.el5_7.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-process", rpm:"php-process~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"php-zts", rpm:"php-zts~5.3.3~3.el6_2.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

