###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kdelibs RHSA-2012:1416-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-October/msg00034.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870857");
  script_version("2020-02-18T15:18:54+0000");
  script_tag(name:"last_modification", value:"2020-02-18 15:18:54 +0000 (Tue, 18 Feb 2020)");
  script_tag(name:"creation_date", value:"2012-11-02 10:59:53 +0530 (Fri, 02 Nov 2012)");
  script_cve_id("CVE-2012-4512", "CVE-2012-4513");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:1416-01");
  script_name("RedHat Update for kdelibs RHSA-2012:1416-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdelibs'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"kdelibs on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The kdelibs packages provide libraries for the K Desktop Environment
  (KDE). Konqueror is a web browser.

  A heap-based buffer overflow flaw was found in the way the CSS (Cascading
  Style Sheets) parser in kdelibs parsed the location of the source for font
  faces. A web page containing malicious content could cause an application
  using kdelibs (such as Konqueror) to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2012-4512)

  A heap-based buffer over-read flaw was found in the way kdelibs calculated
  canvas dimensions for large images. A web page containing malicious content
  could cause an application using kdelibs to crash or disclose portions of
  its memory. (CVE-2012-4513)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The desktop must be restarted (log out,
  then log back in) for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~4.3.4~14.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-common", rpm:"kdelibs-common~4.3.4~14.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-debuginfo", rpm:"kdelibs-debuginfo~4.3.4~14.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~4.3.4~14.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-apidocs", rpm:"kdelibs-apidocs~4.3.4~14.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
