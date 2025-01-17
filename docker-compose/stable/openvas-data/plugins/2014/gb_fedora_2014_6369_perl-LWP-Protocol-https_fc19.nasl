###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for perl-LWP-Protocol-https FEDORA-2014-6369
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.867823");
  script_version("2020-02-11T08:37:57+0000");
  script_tag(name:"last_modification", value:"2020-02-11 08:37:57 +0000 (Tue, 11 Feb 2020)");
  script_tag(name:"creation_date", value:"2014-05-26 12:54:11 +0530 (Mon, 26 May 2014)");
  script_cve_id("CVE-2014-3230");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Update for perl-LWP-Protocol-https FEDORA-2014-6369");
  script_tag(name:"affected", value:"perl-LWP-Protocol-https on Fedora 19");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"FEDORA", value:"2014-6369");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-May/133616.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-LWP-Protocol-https'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC19");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"perl-LWP-Protocol-https", rpm:"perl-LWP-Protocol-https~6.04~2.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
