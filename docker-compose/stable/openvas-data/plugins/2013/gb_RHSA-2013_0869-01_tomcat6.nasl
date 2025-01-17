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
  script_oid("1.3.6.1.4.1.25623.1.0.871000");
  script_version("2020-03-13T10:06:41+0000");
  script_tag(name:"last_modification", value:"2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2013-05-31 09:50:18 +0530 (Fri, 31 May 2013)");
  script_cve_id("CVE-2013-1976", "CVE-2013-2051", "CVE-2012-5887");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for tomcat6 RHSA-2013:0869-01");

  script_xref(name:"RHSA", value:"2013:0869-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-May/msg00029.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"tomcat6 on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Apache Tomcat is a servlet container for the Java Servlet and JavaServer
  Pages (JSP) technologies.

  A flaw was found in the way the tomcat6 init script handled the
  tomcat6-initd.log log file. A malicious web application deployed on Tomcat
  could use this flaw to perform a symbolic link attack to change the
  ownership of an arbitrary system file to that of the tomcat user, allowing
  them to escalate their privileges to root. (CVE-2013-1976)

  Note: With this update, tomcat6-initd.log has been moved from
  /var/log/tomcat6/ to the /var/log/ directory.

  It was found that the RHSA-2013:0623 update did not correctly fix
  CVE-2012-5887, a weakness in the Tomcat DIGEST authentication
  implementation. A remote attacker could use this flaw to perform replay
  attacks in some circumstances. Additionally, this problem also prevented
  users from being able to authenticate using DIGEST authentication.
  (CVE-2013-2051)

  Red Hat would like to thank Simon Fayer of Imperial College London for
  reporting the CVE-2013-1976 issue.

  Users of Tomcat are advised to upgrade to these updated packages, which
  correct these issues. Tomcat must be restarted for this update to take
  effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.24~55.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-el-2.1-api", rpm:"tomcat6-el-2.1-api~6.0.24~55.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-jsp-2.1-api", rpm:"tomcat6-jsp-2.1-api~6.0.24~55.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.24~55.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-servlet-2.5-api", rpm:"tomcat6-servlet-2.5-api~6.0.24~55.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
