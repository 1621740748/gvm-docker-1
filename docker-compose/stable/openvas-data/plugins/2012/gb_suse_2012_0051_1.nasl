# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850204");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2012-08-02 20:37:33 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-4862", "CVE-2011-1526");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"openSUSE-SU", value:"2012:0051-1");
  script_name("openSUSE: Security Advisory for krb5-appl (openSUSE-SU-2012:0051-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5-appl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE11\.3)");

  script_tag(name:"affected", value:"krb5-appl on openSUSE 11.4, openSUSE 11.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"This update of krb5 applications fixes two security issues.

  CVE-2011-4862: A remote code execution in the kerberized
  telnet daemon was fixed. (This only affects the ktelnetd
  from the krb5-appl RPM, not the regular telnetd supplied by
  SUSE.)

  CVE-2011-1526 / MITKRB5-SA-2011-005: Fixed krb5 ftpd
  unauthorized file access problems.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

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
  if(!isnull(res = isrpmvuln(pkg:"krb5-appl-clients", rpm:"krb5-appl-clients~1.0~7.12.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-appl-servers", rpm:"krb5-appl-servers~1.0~7.12.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE11.3") {
  if(!isnull(res = isrpmvuln(pkg:"krb5-appl-clients", rpm:"krb5-appl-clients~1.0~4.5.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-appl-servers", rpm:"krb5-appl-servers~1.0~4.5.1", rls:"openSUSE11.3"))) {
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
