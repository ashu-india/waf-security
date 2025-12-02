import { useLocation, Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import {
  LayoutDashboard,
  Shield,
  Globe,
  Settings,
  Bell,
  Activity,
  UserCircle,
  LogOut,
  ChevronDown,
  Zap,
  Brain,
  Lock,
  Sparkles,
  User,
  CheckCircle,
  Layers,
  BarChart3,
  FileText,
  Webhook,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/hooks/useAuth";
import { getUserDisplayName, getUserRole } from "@/lib/authUtils";
import { UserAvatar } from "@/components/user-avatar";

type Alert = any;

const mainNavItems = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard, color: "#0ea5e9" },
  { title: "Tenants", url: "/tenants", icon: Globe, color: "#06b6d4" },
  { title: "Live Traffic", url: "/traffic", icon: Activity, color: "#10b981" },
];

const securityNavItems = [
  { title: "Security Rules", url: "/rules", icon: Shield, color: "#f59e0b" },
  { title: "Policies", url: "/policies", icon: Lock, color: "#ef4444" },
  { title: "DDoS Protection", url: "/ddos-protection", icon: Zap, color: "#f97316" },
  { title: "Attack Testing", url: "/test-attacks", icon: Zap, color: "#ec4899" },
  { title: "ML Analytics", url: "/ml-dashboard", icon: Brain, color: "#8b5cf6" },
  { title: "Alerts", url: "/alerts", icon: Bell, color: "#d946ef" },
];

const complianceNavItems = [
  { title: "Overview", url: "/compliance", icon: CheckCircle, color: "#10b981" },
  { title: "Frameworks", url: "/compliance/frameworks", icon: Layers, color: "#06b6d4" },
  { title: "Comparison", url: "/compliance/comparison", icon: BarChart3, color: "#3b82f6" },
  { title: "Rule Coverage", url: "/compliance/rule-coverage", icon: Shield, color: "#8b5cf6" },
  { title: "Report", url: "/compliance/report", icon: FileText, color: "#f59e0b" },
  { title: "Monitoring", url: "/compliance/monitoring", icon: Activity, color: "#ec4899" },
  { title: "Remediation", url: "/compliance/remediation", icon: Zap, color: "#dc2626" },
  { title: "Webhooks", url: "/compliance/webhooks", icon: Webhook, color: "#06b6d4" },
];

const adminNavItems = [
  { title: "Users", url: "/users", icon: User, color: "#06b6d4" },
  { title: "Settings", url: "/settings", icon: Settings, color: "#6366f1" },
];

export function AppSidebar() {
  const [currentPath] = useLocation();
  const { user } = useAuth();
  const role = getUserRole(user);

  const { data: alerts } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
    refetchInterval: 30000,
  });

  const unreadAlertCount = alerts?.filter((alert) => !alert.isRead).length || 0;

  const isActive = (url: string) => {
    if (url === "/") return currentPath === "/";
    return currentPath.startsWith(url);
  };

  return (
    <Sidebar className="bg-gradient-to-b from-slate-50 via-blue-50 to-slate-50 border-r-2 border-slate-300">
      {/* Header */}
      <SidebarHeader className="border-b-2 border-slate-300 py-4 px-4 bg-gradient-to-r from-white to-blue-50/50">
        <Link to="/" className="flex items-center gap-3 group">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary">
            <Shield className="h-6 w-6 text-primary-foreground" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-semibold text-slate-900">WAF Admin</span>
            <span className="text-xs text-slate-500">Security Dashboard</span>
          </div>
        </Link>
      </SidebarHeader>

      {/* Main Content */}
      <SidebarContent className="py-6 px-3 space-y-6">
        {/* Navigation Section */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-black text-slate-600 uppercase tracking-widest px-2 mb-4 flex items-center gap-2">
            <Sparkles className="w-3.5 h-3.5 text-blue-500" />
            Navigation
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu className="gap-2">
              {mainNavItems.map((item) => {
                const active = isActive(item.url);
                return (
                  <SidebarMenuItem key={item.url}>
                    <SidebarMenuButton
                      asChild
                      className={`
                        relative overflow-hidden group
                        px-4 py-3 rounded-xl transition-all duration-300
                        ${active
                          ? "bg-gradient-to-r from-white via-white to-blue-50 text-slate-900 shadow-md"
                          : "bg-white hover:bg-slate-50 text-slate-700 shadow-sm hover:shadow-md"
                        }
                      `}
                      style={active ? { borderRight: `4px solid ${item.color}` } : {}}
                    >
                      <Link to={item.url} className="flex items-center gap-3 w-full">
                        <div className={`transition-all duration-300 ${active ? "scale-110" : "group-hover:scale-110"}`} style={active ? { color: item.color } : {}}>
                          <item.icon className="w-5 h-5" />
                        </div>
                        <span className={`text-sm font-bold transition-colors duration-300`}>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Security Section */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-black text-slate-600 uppercase tracking-widest px-2 mb-4 flex items-center gap-2">
            <Sparkles className="w-3.5 h-3.5 text-purple-500" />
            Security Suite
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu className="gap-2">
              {securityNavItems.map((item) => {
                const active = isActive(item.url);
                return (
                  <SidebarMenuItem key={item.url}>
                    <SidebarMenuButton
                      asChild
                      className={`
                        relative overflow-hidden group
                        px-4 py-3 rounded-xl transition-all duration-300
                        ${active
                          ? "bg-gradient-to-r from-white via-white to-blue-50 text-slate-900 shadow-md"
                          : "bg-white hover:bg-slate-50 text-slate-700 shadow-sm hover:shadow-md"
                        }
                      `}
                      style={active ? { borderRight: `4px solid ${item.color}` } : {}}
                    >
                      <Link to={item.url} className="flex items-center gap-3 w-full">
                        <div className={`transition-all duration-300 ${active ? "scale-110" : "group-hover:scale-110"}`} style={active ? { color: item.color } : {}}>
                          <item.icon className="w-5 h-5" />
                        </div>
                        <span className={`text-sm font-bold transition-colors duration-300`}>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Compliance Section */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-black text-slate-600 uppercase tracking-widest px-2 mb-4 flex items-center gap-2">
            <Sparkles className="w-3.5 h-3.5 text-green-500" />
            Compliance
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu className="gap-2">
              {complianceNavItems.map((item) => {
                const active = isActive(item.url);
                return (
                  <SidebarMenuItem key={item.url}>
                    <SidebarMenuButton
                      asChild
                      className={`
                        relative overflow-hidden group
                        px-4 py-3 rounded-xl transition-all duration-300
                        ${active
                          ? "bg-gradient-to-r from-white via-white to-blue-50 text-slate-900 shadow-md"
                          : "bg-white hover:bg-slate-50 text-slate-700 shadow-sm hover:shadow-md"
                        }
                      `}
                      style={active ? { borderRight: `4px solid ${item.color}` } : {}}
                    >
                      <Link to={item.url} className="flex items-center gap-3 w-full">
                        <div className={`transition-all duration-300 ${active ? "scale-110" : "group-hover:scale-110"}`} style={active ? { color: item.color } : {}}>
                          <item.icon className="w-5 h-5" />
                        </div>
                        <span className={`text-sm font-bold transition-colors duration-300`}>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Admin Section */}
        {role === "admin" && (
          <SidebarGroup>
            <SidebarGroupLabel className="text-xs font-black text-slate-600 uppercase tracking-widest px-2 mb-4 flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-slate-500" />
              Administration
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu className="gap-2">
                {adminNavItems.map((item) => {
                  const active = isActive(item.url);
                  return (
                    <SidebarMenuItem key={item.url}>
                      <SidebarMenuButton
                        asChild
                        className={`
                          relative overflow-hidden group
                          px-4 py-3 rounded-xl transition-all duration-300
                          ${active
                            ? "bg-gradient-to-r from-white via-white to-blue-50 text-slate-900 shadow-md"
                            : "bg-white hover:bg-slate-50 text-slate-700 shadow-sm hover:shadow-md"
                          }
                        `}
                        style={active ? { borderRight: `4px solid ${item.color}` } : {}}
                      >
                        <Link to={item.url} className="flex items-center gap-3 w-full">
                          <div className={`transition-all duration-300 ${active ? "scale-110" : "group-hover:scale-110"}`} style={active ? { color: item.color } : {}}>
                            <item.icon className="w-5 h-5" />
                          </div>
                          <span className={`text-sm font-bold transition-colors duration-300`}>{item.title}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}

        {/* Alert Banner */}
        {unreadAlertCount > 0 && (
          <div className="mx-1 mt-6 p-4 bg-gradient-to-br from-red-50 via-rose-50 to-pink-50 border border-red-200/50 rounded-xl shadow-md hover:shadow-lg transition-shadow">
            <div className="flex items-start gap-3">
              <div className="relative mt-0.5">
                <div className="absolute inset-0 bg-red-400 rounded-full blur-sm opacity-50"></div>
                <Bell className="w-5 h-5 text-red-600 relative" />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-900">
                  {unreadAlertCount} Alert{unreadAlertCount > 1 ? "s" : ""}
                </p>
                <p className="text-xs text-slate-600 mt-1">Review security events</p>
              </div>
            </div>
          </div>
        )}
      </SidebarContent>

      {/* Footer */}
      <SidebarFooter className="border-t-2 border-slate-300 py-4 px-2 bg-gradient-to-r from-white to-blue-50/30">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="w-full px-3 py-3 rounded-xl transition-all duration-200 bg-white hover:bg-gradient-to-r hover:from-blue-50 hover:to-purple-50 flex items-center gap-3 group shadow-sm hover:shadow-md">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-br from-blue-400 to-purple-500 rounded-lg blur-sm opacity-0 group-hover:opacity-50 transition-opacity"></div>
                <UserAvatar user={user} size="md" showRole={true} />
              </div>
              <div className="flex-1 min-w-0 text-left">
                <p className="text-sm font-bold text-slate-900 truncate">
                  {getUserDisplayName(user)}
                </p>
                <Badge className="text-xs bg-gradient-to-r from-blue-100 to-purple-100 text-slate-700 border-0 font-bold mt-1">
                  {getUserRole(user).toUpperCase()}
                </Badge>
              </div>
              <ChevronDown className="w-4 h-4 text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52 bg-white border border-slate-200/50">
            <div className="px-3 py-2 text-xs font-bold text-slate-600 border-b border-slate-100">
              {user?.email || "User Account"}
            </div>
            <DropdownMenuSeparator className="bg-slate-100/50" />
            <DropdownMenuItem asChild className="cursor-pointer">
              <Link to="/settings" className="flex items-center gap-2 px-2 py-2">
                <div className="p-1.5 bg-slate-100 rounded-lg">
                  <Settings className="w-4 h-4 text-slate-600" />
                </div>
                <span className="text-sm font-bold text-slate-900">Settings</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator className="bg-slate-100/50" />
            <DropdownMenuItem
              onClick={async () => {
                try {
                  await fetch("/api/auth/logout", { 
                    method: "GET",
                    credentials: "include"
                  });
                  window.location.href = "/";
                } catch (error) {
                  console.error("Logout error:", error);
                  window.location.href = "/";
                }
              }}
              className="text-red-600 cursor-pointer"
            >
              <LogOut className="w-4 h-4 mr-2" />
              <span className="text-sm font-bold">Logout</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarFooter>
    </Sidebar>
  );
}
