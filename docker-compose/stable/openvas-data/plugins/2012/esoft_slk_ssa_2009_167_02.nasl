# OpenVAS Vulnerability Test
# Description: Auto-generated from the corresponding slackware advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64259");
  script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
  script_tag(name:"last_modification", value:"2020-10-16 09:11:00 +0000 (Fri, 16 Oct 2020)");
  script_cve_id("CVE-2009-0023", "CVE-2009-1955");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2020-10-16T09:11:00+0000");
  script_name("Slackware Advisory SSA:2009-167-02 apr-util");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(11\.0|12\.0|12\.1|12\.2)");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2009-167-02");

  script_tag(name:"insight", value:"New apr-util (and apr) packages are available for Slackware 11.0, 12.0, 12.1,
12.2, and -current to fix security issues.  The issues are with apr-util, but
older Slackware releases will require a new version of the apr package as well.");

  script_tag(name:"solution", value:"Upgrade to the new package(s).");

  script_tag(name:"summary", value:"The remote host is missing an update as announced
via advisory SSA:2009-167-02.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

report = "";
res = "";

if((res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1_slack11.0", rls:"SLK11.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1_slack11.0", rls:"SLK11.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1_slack12.0", rls:"SLK12.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1_slack12.0", rls:"SLK12.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1_slack12.1", rls:"SLK12.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1_slack12.1", rls:"SLK12.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1_slack12.2", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1_slack12.2", rls:"SLK12.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}