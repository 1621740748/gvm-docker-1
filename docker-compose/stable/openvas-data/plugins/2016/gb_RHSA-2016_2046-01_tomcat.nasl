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
  script_oid("1.3.6.1.4.1.25623.1.0.871670");
  script_version("2020-03-13T10:06:41+0000");
  script_tag(name:"last_modification", value:"2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2016-10-11 06:32:10 +0200 (Tue, 11 Oct 2016)");
  script_cve_id("CVE-2014-7810", "CVE-2015-5346", "CVE-2016-5388", "CVE-2016-5425",
                "CVE-2016-6325");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for tomcat RHSA-2016:2046-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Apache Tomcat is a servlet container for
the Java Servlet and JavaServer Pages (JSP) technologies.

Security Fix(es):

  * It was discovered that the Tomcat packages installed configuration file
/usr/lib/tmpfiles.d/tomcat.conf writeable to the tomcat group. A member of
the group or a malicious web application deployed on Tomcat could use this
flaw to escalate their privileges. (CVE-2016-5425)

  * It was discovered that the Tomcat packages installed certain
configuration files read by the Tomcat initialization script as writeable
to the tomcat group. A member of the group or a malicious web application
deployed on Tomcat could use this flaw to escalate their privileges.
(CVE-2016-6325)

  * It was found that the expression language resolver evaluated expressions
within a privileged code section. A malicious web application could use
this flaw to bypass security manager protections. (CVE-2014-7810)

  * It was discovered that tomcat used the value of the Proxy header from
HTTP requests to initialize the HTTP_PROXY environment variable for CGI
scripts, which in turn was incorrectly used by certain HTTP client
implementations to configure the proxy for outgoing HTTP requests. A remote
attacker could possibly use this flaw to redirect HTTP requests performed
by a CGI script to an attacker-controlled proxy via a malicious HTTP
request. (CVE-2016-5388)

  * A session fixation flaw was found in the way Tomcat recycled the
requestedSessionSSL field. If at least one web application was configured
to use the SSL session ID as the HTTP session ID, an attacker could reuse a
previously used session ID for further requests. (CVE-2015-5346)

Red Hat would like to thank Dawid Golunski for
reporting CVE-2016-5425 and Scott Geary (VendHQ) for reporting
CVE-2016-5388. The CVE-2016-6325 issue was discovered by Red Hat Product
Security.");
  script_tag(name:"affected", value:"tomcat on
  Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:2046-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-October/msg00019.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.54~8.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.54~8.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-el-2.2-api", rpm:"tomcat-el-2.2-api~7.0.54~8.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-jsp-2.2-api", rpm:"tomcat-jsp-2.2-api~7.0.54~8.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.54~8.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-servlet-3.0-api", rpm:"tomcat-servlet-3.0-api~7.0.54~8.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.54~8.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
