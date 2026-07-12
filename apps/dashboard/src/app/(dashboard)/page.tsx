import {
  Bot,
  CreditCard,
  Filter,
  LineChart,
  MoreHorizontal,
  Search,
  Settings,
  Sparkles,
} from "lucide-react";

type StatCard = {
  title: string;
  value: string;
  change: string;
  tone: "orange" | "white";
};

type ActivityRow = {
  id: string;
  activity: string;
  price: string;
  status: "Completed" | "Pending" | "In Progress";
  date: string;
};

const stats: StatCard[] = [
  {
    title: "Total Earnings",
    value: "$950",
    change: "+7.8% This month",
    tone: "orange",
  },
  {
    title: "Tasks Completed",
    value: "700",
    change: "+5.1% This month",
    tone: "white",
  },
  {
    title: "Agent Actions",
    value: "1,050",
    change: "+8.5% This month",
    tone: "white",
  },
  {
    title: "Protected Events",
    value: "850",
    change: "+4.4% This month",
    tone: "white",
  },
];

const activities: ActivityRow[] = [
  {
    id: "TASK_000076",
    activity: "Memory write approved",
    price: "$25,500",
    status: "Completed",
    date: "17 Apr, 2026 03:45 PM",
  },
  {
    id: "TASK_000075",
    activity: "Security review routed",
    price: "$32,750",
    status: "Pending",
    date: "15 Apr, 2026 11:30 AM",
  },
  {
    id: "TASK_000074",
    activity: "Workflow automation run",
    price: "$40,200",
    status: "Completed",
    date: "15 Apr, 2026 12:00 PM",
  },
  {
    id: "TASK_000073",
    activity: "Verification payload created",
    price: "$50,200",
    status: "In Progress",
    date: "14 Apr, 2026 09:15 PM",
  },
  {
    id: "TASK_000072",
    activity: "Agent registry synced",
    price: "$15,900",
    status: "Completed",
    date: "10 Apr, 2026 06:00 AM",
  },
];

const wallets = [
  {
    label: "Workspace Usage",
    value: "$22,678.00",
    meta: "4.5% from last month",
  },
  {
    label: "Security Queue",
    value: "$18,345.00",
    meta: "2.4% from last month",
  },
  {
    label: "Memory Events",
    value: "$15,000.00",
    meta: "1.6% from last month",
  },
];

const chartData = [
  { month: "Jan", profit: 38, loss: 16 },
  { month: "Feb", profit: 42, loss: 20 },
  { month: "Mar", profit: 31, loss: 18 },
  { month: "Apr", profit: 37, loss: 22 },
  { month: "May", profit: 48, loss: 15 },
  { month: "Jun", profit: 54, loss: 23 },
  { month: "Jul", profit: 41, loss: 19 },
  { month: "Aug", profit: 33, loss: 16 },
];

function StatusBadge({ status }: { status: ActivityRow["status"] }) {
  const classes = {
    Completed: "bg-emerald-50 text-emerald-700",
    Pending: "bg-red-50 text-red-700",
    "In Progress": "bg-amber-50 text-amber-700",
  };

  return (
    <span
      className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-semibold ${classes[status]}`}
    >
      {status}
    </span>
  );
}

function MiniBarChart() {
  return (
    <div className="mt-5 flex h-[190px] items-end justify-between gap-3 rounded-[24px] bg-[#fafafa] px-5 pb-5 pt-6">
      {chartData.map((item) => (
        <div
          key={item.month}
          className="flex flex-1 flex-col items-center gap-2"
        >
          <div className="flex h-[130px] items-end gap-1.5">
            <div
              className="w-3 rounded-t-full bg-[#ff6a3d]"
              style={{ height: `${item.profit * 2}px` }}
            />
            <div
              className="w-3 rounded-t-full bg-[#151515]"
              style={{ height: `${item.loss * 2}px` }}
            />
          </div>
          <span className="text-[10px] font-medium text-zinc-400">
            {item.month}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function Page() {
  return (
    <div className="text-[#161616]">
      <div className="mb-6">
        <h1 className="text-3xl font-black tracking-tight text-[#141414]">
          Good morning, Saijbur
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          Stay on top of your agents, monitor progress, and track workspace
          performance.
        </p>
      </div>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-[1.1fr_1fr_1fr]">
        <div className="rounded-[26px] bg-white p-5 shadow-sm ring-1 ring-zinc-100">
          <div className="mb-5 flex items-start justify-between">
            <div>
              <p className="text-xs font-semibold text-zinc-500">
                Total Balance
              </p>
              <h2 className="mt-2 text-3xl font-black tracking-tight">
                $689,372.00
              </h2>
              <p className="mt-1 text-xs font-bold text-emerald-600">
                +5% from last month
              </p>
            </div>
            <button className="rounded-full bg-zinc-50 px-3 py-1.5 text-xs font-bold text-zinc-600">
              USD
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <button className="rounded-full bg-[#171717] px-4 py-3 text-xs font-bold text-white">
              Transfer
            </button>
            <button className="rounded-full bg-zinc-100 px-4 py-3 text-xs font-bold text-zinc-700">
              Request
            </button>
          </div>

          <div className="mt-5">
            <div className="mb-3 flex items-center justify-between">
              <p className="text-xs font-bold text-zinc-700">Wallets</p>
              <p className="text-[11px] text-zinc-400">Total 6 wallets</p>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              {wallets.map((wallet) => (
                <div
                  key={wallet.label}
                  className="rounded-[18px] bg-[#fafafa] p-3 ring-1 ring-zinc-100"
                >
                  <p className="text-[10px] font-bold uppercase text-zinc-400">
                    {wallet.label}
                  </p>
                  <p className="mt-2 text-sm font-black">{wallet.value}</p>
                  <p className="mt-1 text-[10px] text-zinc-400">
                    {wallet.meta}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          {stats.map((stat) => (
            <div
              key={stat.title}
              className={`rounded-[26px] p-5 shadow-sm ring-1 ${
                stat.tone === "orange"
                  ? "bg-gradient-to-br from-[#ff8a57] to-[#ff4b2b] text-white ring-orange-200"
                  : "bg-white text-[#171717] ring-zinc-100"
              }`}
            >
              <div className="flex items-center justify-between">
                <p
                  className={`text-xs font-semibold ${stat.tone === "orange" ? "text-white/80" : "text-zinc-500"}`}
                >
                  {stat.title}
                </p>
                <MoreHorizontal
                  className={`h-4 w-4 ${stat.tone === "orange" ? "text-white/70" : "text-zinc-400"}`}
                />
              </div>
              <h3 className="mt-5 text-3xl font-black">{stat.value}</h3>
              <p
                className={`mt-2 text-xs font-bold ${stat.tone === "orange" ? "text-white/85" : "text-emerald-600"}`}
              >
                {stat.change}
              </p>
            </div>
          ))}
        </div>

        <div className="rounded-[26px] bg-white p-5 shadow-sm ring-1 ring-zinc-100">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-sm font-black">Total Income</p>
              <p className="mt-1 text-xs text-zinc-500">
                View your income in a certain period of time
              </p>
            </div>
            <LineChart className="h-5 w-5 text-zinc-400" />
          </div>

          <div className="mt-4 flex items-center gap-4 text-xs font-semibold">
            <span className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-[#ff6a3d]" />
              Profit
            </span>
            <span className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-[#171717]" />
              Loss
            </span>
          </div>

          <MiniBarChart />
        </div>
      </section>

      <section className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-[0.8fr_1.6fr]">
        <div className="space-y-5">
          <div className="rounded-[26px] bg-white p-5 shadow-sm ring-1 ring-zinc-100">
            <div className="mb-4 flex items-center justify-between">
              <p className="text-sm font-black">Monthly Spending Limit</p>
              <Settings className="h-4 w-4 text-zinc-400" />
            </div>

            <div className="h-3 overflow-hidden rounded-full bg-zinc-100">
              <div className="h-full w-[42%] rounded-full bg-[#ff5b2e]" />
            </div>

            <div className="mt-3 flex items-center justify-between text-[11px] font-semibold text-zinc-500">
              <span>$1,400.00 spent out of</span>
              <span>$5,500.00</span>
            </div>
          </div>

          <div className="rounded-[26px] bg-white p-5 shadow-sm ring-1 ring-zinc-100">
            <div className="mb-4 flex items-center justify-between">
              <p className="text-sm font-black">My Cards</p>
              <button className="rounded-full bg-zinc-100 px-3 py-1.5 text-[11px] font-bold">
                + Add new
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="min-h-[140px] rounded-[24px] bg-[#171717] p-4 text-white">
                <div className="flex items-center justify-between">
                  <span className="rounded-full bg-white/10 px-2 py-1 text-[10px] font-bold">
                    Active
                  </span>
                  <CreditCard className="h-5 w-5 text-white/70" />
                </div>
                <div className="mt-10">
                  <p className="text-[10px] text-white/50">Card Number</p>
                  <p className="mt-1 text-xs font-bold tracking-widest">
                    **** **** 6762
                  </p>
                </div>
              </div>

              <div className="min-h-[140px] rounded-[24px] bg-gradient-to-br from-[#ff8657] to-[#ff4b2b] p-4 text-white">
                <div className="flex items-center justify-between">
                  <span className="rounded-full bg-white/20 px-2 py-1 text-[10px] font-bold">
                    Active
                  </span>
                  <Sparkles className="h-5 w-5 text-white/80" />
                </div>
                <div className="mt-10">
                  <p className="text-[10px] text-white/70">Card Number</p>
                  <p className="mt-1 text-xs font-bold tracking-widest">
                    **** **** 4356
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-[26px] bg-white p-5 shadow-sm ring-1 ring-zinc-100">
          <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <p className="text-sm font-black">Recent Activities</p>

            <div className="flex items-center gap-3">
              <div className="flex h-10 w-full min-w-[220px] items-center gap-2 rounded-full bg-[#fafafa] px-4 ring-1 ring-zinc-100 md:w-auto">
                <Search className="h-4 w-4 text-zinc-400" />
                <span className="text-xs text-zinc-400">Search</span>
              </div>
              <button className="flex h-10 items-center gap-2 rounded-full bg-[#fafafa] px-4 text-xs font-bold text-zinc-600 ring-1 ring-zinc-100">
                Filter
                <Filter className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <div className="overflow-hidden rounded-[22px] ring-1 ring-zinc-100">
            <table className="w-full min-w-[760px] border-collapse bg-white text-left">
              <thead>
                <tr className="bg-[#fafafa] text-[11px] font-bold uppercase text-zinc-400">
                  <th className="px-4 py-4">
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-zinc-300"
                    />
                  </th>
                  <th className="px-4 py-4">Order ID</th>
                  <th className="px-4 py-4">Activity</th>
                  <th className="px-4 py-4">Price</th>
                  <th className="px-4 py-4">Status</th>
                  <th className="px-4 py-4">Date</th>
                  <th className="px-4 py-4" />
                </tr>
              </thead>
              <tbody>
                {activities.map((row, index) => (
                  <tr
                    key={`${row.id}-${index}`}
                    className="border-t border-zinc-100 text-xs"
                  >
                    <td className="px-4 py-4">
                      <input
                        type="checkbox"
                        className="h-4 w-4 rounded border-zinc-300"
                        defaultChecked={index === 3}
                      />
                    </td>
                    <td className="px-4 py-4 font-bold text-zinc-600">
                      {row.id}
                    </td>
                    <td className="px-4 py-4">
                      <span className="flex items-center gap-2 font-semibold">
                        <span className="flex h-7 w-7 items-center justify-center rounded-xl bg-orange-50 text-orange-600">
                          <Bot className="h-3.5 w-3.5" />
                        </span>
                        {row.activity}
                      </span>
                    </td>
                    <td className="px-4 py-4 font-bold">{row.price}</td>
                    <td className="px-4 py-4">
                      <StatusBadge status={row.status} />
                    </td>
                    <td className="px-4 py-4 text-zinc-500">{row.date}</td>
                    <td className="px-4 py-4">
                      <MoreHorizontal className="h-4 w-4 text-zinc-400" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}
