###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for rubygem-rack FEDORA-2013-0861
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-January/097523.html");
  script_oid("1.3.6.1.4.1.25623.1.0.865250");
  script_version("2021-07-02T11:00:44+0000");
  script_tag(name:"last_modification", value:"2021-07-02 11:00:44 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2013-01-28 09:34:23 +0530 (Mon, 28 Jan 2013)");
  script_cve_id("CVE-2011-6109", "CVE-2013-0183", "CVE-2013-0184", "CVE-2012-6109");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"FEDORA", value:"2013-0861");
  script_name("Fedora Update for rubygem-rack FEDORA-2013-0861");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-rack'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC17");
  script_tag(name:"affected", value:"rubygem-rack on Fedora 17");
  script_tag(name:"solution", value:"Please install the updated package(s).");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"rubygem-rack", rpm:"rubygem-rack~1.4.0~3.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
