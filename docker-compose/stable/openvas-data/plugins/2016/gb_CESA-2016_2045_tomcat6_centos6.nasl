# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.882576");
  script_version("2020-03-13T10:06:41+0000");
  script_tag(name:"last_modification", value:"2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2016-10-12 05:45:01 +0200 (Wed, 12 Oct 2016)");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2016-0706", "CVE-2016-0714",
                "CVE-2016-5388", "CVE-2016-6325");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for tomcat6 CESA-2016:2045 centos6");
  script_tag(name:"summary", value:"Check the version of tomcat6");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Apache Tomcat is a servlet container for
the Java Servlet and JavaServer Pages (JSP) technologies.

Security Fix(es):

  * It was discovered that the Tomcat packages installed certain
configuration files read by the Tomcat initialization script as writeable
to the tomcat group. A member of the group or a malicious web application
deployed on Tomcat could use this flaw to escalate their privileges.
(CVE-2016-6325)

  * It was found that several Tomcat session persistence mechanisms could
allow a remote, authenticated user to bypass intended SecurityManager
restrictions and execute arbitrary code in a privileged context via a web
application that placed a crafted object in a session. (CVE-2016-0714)

  * It was discovered that tomcat used the value of the Proxy header from
HTTP requests to initialize the HTTP_PROXY environment variable for CGI
scripts, which in turn was incorrectly used by certain HTTP client
implementations to configure the proxy for outgoing HTTP requests. A remote
attacker could possibly use this flaw to redirect HTTP requests performed
by a CGI script to an attacker-controlled proxy via a malicious HTTP
request. (CVE-2016-5388)

  * A directory traversal flaw was found in Tomcat's RequestUtil.java. A
remote, authenticated user could use this flaw to bypass intended
SecurityManager restrictions and list a parent directory via a '/..' in a
pathname used by a web application in a getResource, getResourceAsStream,
or getResourcePaths call, as demonstrated by the $CATALINA_BASE/webapps
directory. (CVE-2015-5174)

  * It was found that Tomcat could reveal the presence of a directory even
when that directory was protected by a security constraint. A user could
make a request to a directory via a URL not ending with a slash and,
depending on whether Tomcat redirected that request, could confirm whether
that directory existed. (CVE-2015-5345)

  * It was found that Tomcat allowed the StatusManagerServlet to be loaded by
a web application when a security manager was configured. This allowed a
web application to list all deployed web applications and expose sensitive
information such as session IDs. (CVE-2016-0706)

Red Hat would like to thank Scott Geary (VendHQ) for reporting
CVE-2016-5388. The CVE-2016-6325 issue was discovered by Red Hat Product
Security.

Bug Fix(es):

  * Due to a bug in the tomcat6 spec file, the catalina.out file's md5sum,
size, and mtime attributes were compared to the file's attributes at
installation time. Because these attributes change after the service is
started, the 'rpm -V' command previously failed. With this update, the
attributes mentioned above are ignored in the RPM verification and the
catalina.out file now passes the verification check. (BZ#1357123)");
  script_tag(name:"affected", value:"tomcat6 on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:2045");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-October/022119.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-el-2.1-api", rpm:"tomcat6-el-2.1-api~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-jsp-2.1-api", rpm:"tomcat6-jsp-2.1-api~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-servlet-2.5-api", rpm:"tomcat6-servlet-2.5-api~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.24~98.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
