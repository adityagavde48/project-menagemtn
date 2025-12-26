const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const cron = require("node-cron");
const multer = require("multer"); // ✅ declared ONCE
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

/* ================= DATABASE ================= */

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

/* ================= MODELS ================= */

// USER (NO GLOBAL ROLE)
const UserSchema = new mongoose.Schema({
  name: String,
  phone: String,
  email: { type: String, unique: true },
  password: String,
});
const User = mongoose.model("User", UserSchema);

// PROJECT (PROJECT-SCOPED ROLES)
const ProjectSchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    requirements: [String], // ✅ NEW

    owner: {
      userId: mongoose.Schema.Types.ObjectId,
      email: String,
    },

    manager: {
      userId: mongoose.Schema.Types.ObjectId,
      email: String,
      status: { type: String, enum: ["pending", "accepted"], default: "pending" },
    },

   team: [
  {
    userId: mongoose.Schema.Types.ObjectId,
    email: String,
    role: { type: String, enum: ["SCRUM_MASTER", "TEAM_MEMBER"] },
    status: { type: String, enum: ["pending", "accepted"], default: "pending" },
  },
],


    requirementPdfPath: String,
    projectDeadline: Date,

    status: {
      type: String,
      enum: ["pending", "active", "rejected"],
      default: "pending",
    },
  },
  { timestamps: true }
);
const Project = mongoose.model("Project", ProjectSchema);

// TASK
const TaskSchema = new mongoose.Schema(
  {
    // ✅ TASK NUMBER (SECTION NUMBER: 1,2,3…)
    taskNumber: {
      type: Number,
      required: true,
    },

    title: {
      type: String,
      required: true,
    },

    description: String,

    projectId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },

    assignedTo: mongoose.Schema.Types.ObjectId,

    // ✅ STRONG DEADLINE (REQUIRED)
    deadline: {
      type: Date,
      required: true,
    },

    status: {
      type: String,
      enum: ["todo", "in-progress", "done"],
      default: "todo",
    },

    // ✅ DAY-BY-DAY TASK UPDATES (MEMBER ACTIVITY)
    dailyUpdates: [
      {
        date: {
          type: Date,
          default: Date.now,
        },
        status: {
          type: String,
          enum: ["in-progress", "done"],
        },
        note: {
          type: String,
          required: true,
        },
        updatedBy: {
          type: mongoose.Schema.Types.ObjectId,
          required: true,
        },
      },
    ],
  },
  { timestamps: true }
);

// ✅ ENSURE UNIQUE TASK NUMBER PER PROJECT (VERY IMPORTANT)
TaskSchema.index({ projectId: 1, taskNumber: 1 }, { unique: true });


const Task = mongoose.model("Task", TaskSchema);

// NOTIFICATION
// ================= NOTIFICATION MODEL =================
const NotificationSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },

    projectId: {
      type: mongoose.Schema.Types.ObjectId,
    },

    taskId: {
      type: mongoose.Schema.Types.ObjectId,
    },

    type: {
      type: String,
      enum: [
        "project-invite",
        "team-add",
        "task-assign",
        "deadline-alert",
      ],
      required: true,
    },

    message: {
      type: String,
      required: true,
    },

    isRead: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
  
);

const Notification = mongoose.model("Notification", NotificationSchema);

/* ================= AUTH ================= */

function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(
      authHeader.split(" ")[1],
      process.env.JWT_SECRET
    );

    // ✅ keep ObjectId directly
    req.user = { id: decoded._id };
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

/* ================= ROLE RESOLVER ================= */
/*
  This function checks what role a user has in a project.
  It is used by dashboard & task APIs.
*/
function getUserRoleInProject(project, userId) {

  // 1️⃣ OWNER check
  if (project.owner?.userId?.toString() === userId.toString()) {
    return "OWNER";
  }

  // 2️⃣ MANAGER check
  if (project.manager?.userId?.toString() === userId.toString()) {
    return "MANAGER";
  }

  // 3️⃣ TEAM MEMBER / SCRUM MASTER check
  const member = project.team.find(
    (m) => m.userId.toString() === userId.toString()
  );

  if (member) {
    return member.role || "TEAM_MEMBER";
  }

  // 4️⃣ Not part of project
  return null;
}


/* ================= FILE UPLOAD ================= */

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");


const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage,
  fileFilter: function (req, file, cb) {
    const allowedExt = [
      ".pdf",
      ".txt",
      ".py",
      ".java",
      ".c",
      ".cpp",
      ".doc",
      ".docx",
      ".ppt",
      ".pptx",
    ];

    const ext = path.extname(file.originalname).toLowerCase();

    if (allowedExt.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error("File type not allowed"));
    }
  },
});

/* ================= AUTH APIs ================= */

app.post("/api/auth/signup", async (req, res) => {
  const { name, phone, email, password } = req.body;

  if (await User.findOne({ email }))
    return res.status(400).json({ message: "User already exists" });

  const hash = await bcrypt.hash(password, 10);
  await User.create({ name, phone, email, password: hash });

  res.json({ message: "Signup successful" });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ message: "Invalid credentials" });

const token = jwt.sign(
  { _id: user._id },   // ✅ store ObjectId correctly
  process.env.JWT_SECRET,
  { expiresIn: "1d" }
);

  res.json({ token });
});

/* ================= USER SEARCH ================= */

app.get("/api/users/search", auth, async (req, res) => {
  const query = req.query.query || "";
  const users = await User.find({
    email: { $regex: query, $options: "i" },
  })
    .limit(10)
    .select("email");
  res.json(users);
});

/* ================= CREATE PROJECT ================= */

app.post(
  "/api/projects",
  auth,
  upload.single("requirementPdf"),
  async (req, res) => {
    const { title, description, managerEmail } = req.body;

    const owner = await User.findById(req.user.id);
    const manager = await User.findOne({ email: managerEmail });

    if (!manager)
      return res.status(404).json({ message: "Manager email not found" });

    const project = await Project.create({
      title,
      description,
      owner: { userId: owner._id, email: owner.email },
      manager: { userId: manager._id, email: manager.email },
      requirementPdfPath: req.file?.path,
    });

   await Notification.create({
  userId: manager._id,
  projectId: project._id,
  type: "project-invite",
  message: `You have been invited to manage project "${project.title}"`,
});


    res.json({
      message: "Project created & manager invited",
      projectId: project._id,
    });
  }
);

/* ================= PROJECT DETAILS ================= */
app.get("/api/projects/:id", auth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }

    const project = await Project.findById(id);
    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    // 🔐 access check
    const role = getUserRoleInProject(project, req.user.id);
    if (!role) {
      return res.status(403).json({ message: "Access denied" });
    }

    res.json({
      id: project._id,
      title: project.title,
      description: project.description,
      requirements: project.requirements || [],
      requirementFileUrl: project.requirementPdfPath
        ? `http://localhost:5000/uploads/${path.basename(
            project.requirementPdfPath
          )}`
        : null,
      projectDeadline: project.projectDeadline,
      status: project.status,
      role,
      createdAt: project.createdAt,
      updatedAt: project.updatedAt,
    });

  } catch (err) {
    console.error("PROJECT FETCH ERROR:", err);
    res.status(500).json({ message: "Failed to load project" });
  }
});

/* ================= MANAGER EMAIL SUGGESTIONS ================= */

app.get("/api/managers", auth, async (req, res) => {
  console.log("📥 /api/managers HIT");
  console.log("🔑 User:", req.user.id);
  console.log("🔍 Query:", req.query.query);

  try {
    const query = (req.query.query || "").trim();

    if (!query) return res.json([]);

    const users = await User.find({
      email: { $regex: query, $options: "i" },
    })
      .limit(10)
      .select("email -_id");

    console.log("📤 Results:", users.length);
    res.json(users);

  } catch (err) {
    console.error("MANAGER SEARCH ERROR:", err);
    res.status(500).json([]);
  }
});


/* ================= TASK UPDATE (ROLE BASED) ================= */
/*
  Only MANAGER and SCRUM_MASTER can update task status
*/
app.put("/api/tasks/:taskId", auth, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status } = req.body;
    const userId = req.user.id;

    // 1️⃣ Find task
    const task = await Task.findById(taskId);
    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // 2️⃣ Find project of this task
    const project = await Project.findById(task.projectId);
    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    // 3️⃣ Get role using MODULE 1
    const role = getUserRoleInProject(project, userId);

    // 4️⃣ Permission check
    if (role !== "MANAGER" && role !== "SCRUM_MASTER") {
      return res.status(403).json({
        message: "Only Manager or Scrum Master can update tasks",
      });
    }

    // 5️⃣ Update task
    task.status = status;
    await task.save();

    res.json({ message: "Task updated successfully" });

  } catch (error) {
    console.error("TASK UPDATE ERROR:", error);
    res.status(500).json({ message: "Server error" });
  }
});


/* ================= ACCEPT / REJECT PROJECT ================= */


app.put("/api/projects/:id/accept", auth, async (req, res) => {
  const project = await Project.findById(req.params.id);

  if (!project)
    return res.status(404).json({ message: "Project not found" });

  if (project.manager.userId.toString() !== req.user.id)
    return res.status(403).json({ message: "Unauthorized" });

  project.manager.status = "accepted";
  project.status = "active";
  await project.save();

  res.json({
    message: "Project accepted",
    redirect: `manager-setup.html?projectId=${project._id}`,
  });
});
app.put("/api/projects/:id/reject", auth, async (req, res) => {
  const project = await Project.findById(req.params.id);

  if (!project)
    return res.status(404).json({ message: "Project not found" });

  if (project.manager.userId.toString() !== req.user.id)
    return res.status(403).json({ message: "Unauthorized" });

  project.status = "rejected";
  await project.save();

  res.json({ message: "Project rejected" });
});
/* ================= DELETE PROJECT (OWNER ONLY) ================= */

app.delete("/api/projects/:id", auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);

    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    if (project.owner.userId.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ message: "Only owner can delete project" });
    }

    await Task.deleteMany({ projectId: project._id });
    await Notification.deleteMany({ projectId: project._id });
    await MemberUpload.deleteMany({ projectId: project._id });
    await ProjectChat.deleteMany({ projectId: project._id });

    await Project.deleteOne({ _id: project._id });

    res.json({ message: "Project deleted successfully" });
  } catch (err) {
    console.error("DELETE PROJECT ERROR:", err);
    res.status(500).json({ message: "Project deletion failed" });
  }
});
  
/* ================= MANAGER SETUP ================= */

app.post("/api/projects/:id/manager-setup", auth, async (req, res) => {
  try {
    const {
      requirements,
      tasks,
      teamMembers,
      assignments,
      projectDeadline,
    } = req.body;

    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    // 🔐 ONLY MANAGER
    if (project.manager.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: "Only manager allowed" });
    }

    // 🔥 REQUIRED FIX — manager must accept first
    if (project.manager.status !== "accepted") {
      return res
        .status(403)
        .json({ message: "Manager must accept project first" });
    }

    // ===== VALIDATION =====
    if (!projectDeadline) {
      return res.status(400).json({ message: "Project deadline required" });
    }

    if (!tasks || tasks.length === 0) {
      return res.status(400).json({ message: "At least one task required" });
    }

    // ===== SAVE PROJECT DATA =====
    project.requirements = requirements || [];
    project.projectDeadline = projectDeadline;

    // ===== RESET TEAM =====
    project.team = [];

    for (const member of teamMembers) {
      const user = await User.findOne({ email: member.email });
      if (!user) continue;

      project.team.push({
        userId: user._id,
        email: user.email,
        role: member.role,
        status: "pending",
      });

      // 🔔 TEAM INVITE (NO DUPLICATES)
      const alreadyInvited = await Notification.findOne({
        userId: user._id,
        projectId: project._id,
        type: "team-add",
      });

      if (!alreadyInvited) {
        await Notification.create({
          userId: user._id,
          projectId: project._id,
          type: "team-add",
          message: `You were added to project "${project.title}"`,
        });
      }
    }

    // ===== RESET OLD TASKS =====
    await Task.deleteMany({ projectId: project._id });

    // ===== CREATE TASKS =====
    const taskMap = {};

    for (let i = 0; i < tasks.length; i++) {
      const t = tasks[i];

      if (!t.deadline) {
        return res
          .status(400)
          .json({ message: `Deadline missing for task ${i + 1}` });
      }

      const task = await Task.create({
        taskNumber: i + 1,
        title: t.title,
        description: t.description,
        projectId: project._id,
        deadline: t.deadline,
        status: "todo",
      });

      taskMap[i + 1] = task;
    }

    // ===== ASSIGN TASKS =====
    for (const a of assignments) {
      const task = taskMap[a.taskNumber];
      const user = await User.findOne({ email: a.assignee });

      if (!task || !user) continue;

      task.assignedTo = user._id;
      await task.save();

      // 🔔 TASK ASSIGN NOTIFICATION (NO DUPLICATES)
      const taskNotifExists = await Notification.findOne({
        userId: user._id,
        taskId: task._id,
        type: "task-assign",
      });

      if (!taskNotifExists) {
        await Notification.create({
          userId: user._id,
          projectId: project._id,
          taskId: task._id,
          type: "task-assign",
          message: `Task ${task.taskNumber}: "${task.title}" assigned to you`,
        });
      }
    }

    await project.save();

    res.json({ message: "Manager setup completed successfully" });

  } catch (err) {
    console.error("MANAGER SETUP ERROR:", err);
    res.status(500).json({ message: "Manager setup failed" });
  }
});

/* ================= TEAM ACCEPT ================= */

app.put("/api/projects/:id/team/accept", auth, async (req, res) => {
  const project = await Project.findById(req.params.id);

  const member = project.team.find(
    (m) => m.userId.toString() === req.user.id
  );

  if (!member)
    return res.status(404).json({ message: "Invite not found" });

  member.status = "accepted"; // ✅ ADDED
  await project.save();       // ✅ ADDED

  res.json({
    message: "Team member accepted",
    redirect: `member-dashboard.html?projectId=${project._id}`,
  });
});
/* ================= TEAM REJECT (ADDED ONLY) ================= */

app.put("/api/projects/:id/team/reject", auth, async (req, res) => {
  const project = await Project.findById(req.params.id);

  project.team = project.team.filter(
    (m) => m.userId.toString() !== req.user.id
  );

  await project.save();

  res.json({ message: "Team invite rejected" });
});

/* ================= NOTIFICATIONS ================= */
// ================= MARK ALL AS READ =================
app.put("/api/notifications/read-all", auth, async (req, res) => {
  try {
    await Notification.updateMany(
      { userId: req.user.id, isRead: false },
      { $set: { isRead: true } }
    );

    res.json({ message: "Notifications marked as read" });
  } catch (err) {
    console.error("READ ALL ERROR:", err);
    res.status(500).json({ message: "Failed to mark notifications as read" });
  }
});

// ================= NOTIFICATIONS =================
// ================= GET NOTIFICATIONS =================
app.get("/api/notifications", auth, async (req, res) => {
  try {
    const notifications = await Notification.find({
      userId: req.user.id,
    })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    res.json(notifications);
  } catch (err) {
    console.error("GET NOTIFICATIONS ERROR:", err);
    res.status(500).json({ message: "Failed to load notifications" });
  }
});

// ================= MEMBER UPLOAD MODEL =================
const MemberUploadSchema = new mongoose.Schema(
  {
    projectId: mongoose.Schema.Types.ObjectId,
    memberId: mongoose.Schema.Types.ObjectId,
    fileName: String,
    filePath: String,
    sprintLabel: String,
    note: String,
  },
  { timestamps: true }
);
const MemberUpload = mongoose.model("MemberUpload", MemberUploadSchema);

// ================= PROJECT CHAT MODEL =================
const ProjectChatSchema = new mongoose.Schema(
  {
    projectId: mongoose.Schema.Types.ObjectId,
    senderId: mongoose.Schema.Types.ObjectId,
    senderName: String,
    message: String,
  },
  { timestamps: true }
);
const ProjectChat = mongoose.model("ProjectChat", ProjectChatSchema);


// ================= MEMBER DASHBOARD (SIMPLE & WORKING) =================
/* ================= MEMBER DASHBOARD (UPDATED – SECTIONS BASED) ================= */
app.get("/api/projects/:projectId/member/dashboard", auth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const userId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(projectId)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }

    const project = await Project.findById(projectId);
    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    // 🔐 SECURITY CHECK
    const role = getUserRoleInProject(project, userId);
    if (!role) {
      return res.status(403).json({ message: "Not a project member" });
    }

    // ===== MEMBER UPLOADS =====
    const uploads = await MemberUpload.find({
      projectId,
      memberId: userId,
    }).lean();

    // ===== SECTIONS (TASKS ACT AS SECTIONS) =====
    const sections = await Task.find({
      projectId,
      assignedTo: userId,
    })
      .select("_id title status updatedAt")
      .lean();

    // ===== CHAT =====
    const chat = await ProjectChat.find({ projectId })
      .sort({ createdAt: 1 })
      .lean();

    res.json({
      project: {
        title: project.title,
        description: project.description,
      },

      stats: {
        totalUploads: uploads.length,
        todayUploads: uploads.filter(
          (u) =>
            new Date(u.createdAt).toDateString() ===
            new Date().toDateString()
        ).length,
        lastUploadAt:
          uploads.length > 0
            ? uploads[uploads.length - 1].createdAt
            : null,
      },

      uploads: uploads.map((u) => ({
        fileName: u.fileName,
        sprintLabel: u.sprintLabel,
        note: u.note,
        uploadedAt: u.createdAt,
        url: `http://localhost:5000/uploads/${path.basename(u.filePath)}`,
      })),

      // ✅ THIS IS WHAT YOUR FRONTEND EXPECTS
      sections: sections.map((s) => ({
        _id: s._id,
        title: s.title,
        status:
          s.status === "in-progress"
            ? "in_progress"
            : s.status === "done"
            ? "done"
            : "not_started",
        updatedAt: s.updatedAt,
      })),

      chat,
    });
  } catch (err) {
    console.error("MEMBER DASHBOARD ERROR:", err);
    res.status(500).json({ message: "Failed to load member dashboard" });
  }
});
/* ================= SECTION STATUS UPDATE (MEMBER) ================= */
/* ================= SECTION STATUS UPDATE (FIXED) ================= */
app.post("/api/sections/:sectionId/update", auth, async (req, res) => {
  try {
    const { sectionId } = req.params;
    const { status } = req.body;
    const userId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(sectionId)) {
      return res.status(400).json({ message: "Invalid section ID" });
    }

    const task = await Task.findById(sectionId);
    if (!task) {
      return res.status(404).json({ message: "Section not found" });
    }

    // 🔐 Only assigned member
    if (task.assignedTo?.toString() !== userId.toString()) {
      return res.status(403).json({ message: "Not your section" });
    }

    // ✅ 🔥 CRITICAL FIX (PREVENTS taskNumber ERROR)
    if (!task.taskNumber) {
      task.taskNumber = 1; // fallback for old data
    }

    // 🔁 Status mapping
    if (status === "done") {
      task.status = "done";
    } else if (status === "in_progress") {
      task.status = "in-progress";
    } else {
      task.status = "todo";
    }

    await task.save(); // ✅ WILL NOT CRASH NOW

    res.json({
      message: "Section updated",
      sectionId: task._id,
      status: task.status,
      updatedAt: task.updatedAt,
    });
  } catch (err) {
    console.error("SECTION UPDATE ERROR:", err);
    res.status(500).json({ message: "Section update failed" });
  }
});

/* ================= SECTION AUTO-RESET (24 HOURS) ================= */
/*
  Every 30 minutes:
  - Find sections (tasks) that are "in-progress"
  - If last update > 24h → reset to "todo"
*/

/* ================= DEADLINE ALERT CRON ================= */
/*
  Runs every 6 hours
  - Finds tasks whose deadline is within next 24 hours
  - Sends ONE notification per task
  - Skips unassigned tasks (🔥 FIX)
*/

cron.schedule("0 */6 * * *", async () => {
  try {
    const soon = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const tasks = await Task.find({
      deadline: { $lte: soon },
      status: { $ne: "done" },
    });

    for (const task of tasks) {
      // 🔥 REQUIRED FIX — prevents crash
      if (!task.assignedTo) continue;

      const exists = await Notification.findOne({
        taskId: task._id,
        type: "deadline-alert",
      });

      if (exists) continue; // 🛑 stop duplicates

      await Notification.create({
        userId: task.assignedTo,
        projectId: task.projectId,
        taskId: task._id,
        type: "deadline-alert",
        message: `⚠️ Deadline approaching for task "${task.title}"`,
      });
    }
  } catch (err) {
    console.error("DEADLINE ALERT ERROR:", err);
  }
});

/* ================= PROJECT DASHBOARD API ================= */
app.get("/api/projects/:id/dashboard", auth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }

    const project = await Project.findById(id);
    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    // 🔐 check user is part of project
    const role = getUserRoleInProject(project, userId);
    if (!role) {
      return res.status(403).json({ message: "Access denied" });
    }

    // ===== TASKS =====
    const tasks = await Task.find({ projectId: project._id });

    // ===== MEMBERS =====
    const members = [];

    // OWNER
    const owner = await User.findById(project.owner.userId);
    if (owner) {
      members.push({
        id: owner._id,
        name: owner.name,
        email: owner.email,
        role: "OWNER",
        progressPercent: 100,
      });
    }

    // MANAGER
    const manager = await User.findById(project.manager.userId);
    if (manager) {
      members.push({
        id: manager._id,
        name: manager.name,
        email: manager.email,
        role: "MANAGER",
        progressPercent: 100,
      });
    }

    // TEAM
    for (const m of project.team.filter(t => t.status === "accepted")) {
      const user = await User.findById(m.userId);
      if (!user) continue;

      const userTasks = tasks.filter(
        t => t.assignedTo?.toString() === user._id.toString()
      );

      const done = userTasks.filter(t => t.status === "done").length;

      members.push({
        id: user._id,
        name: user.name,
        email: user.email,
        role: m.role,
        totalTasks: userTasks.length,
        doneTasks: done,
        overdueTasks: userTasks.filter(
          t => t.deadline && t.deadline < new Date() && t.status !== "done"
        ).length,
        progressPercent: userTasks.length
          ? Math.round((done / userTasks.length) * 100)
          : 0,
      });
    }

    // ===== STATS =====
    const completedTasks = tasks.filter(t => t.status === "done").length;
    const overdueTasks = tasks.filter(
      t => t.deadline && t.deadline < new Date() && t.status !== "done"
    ).length;

    const stats = {
      totalTasks: tasks.length,
      completedTasks,
      overdueTasks,
      activeMembers: members.length,
      completionPercent: tasks.length
        ? Math.round((completedTasks / tasks.length) * 100)
        : 0,
      avgProgress: members.length
        ? Math.round(
            members.reduce((a, b) => a + (b.progressPercent || 0), 0) /
              members.length
          )
        : 0,
    };

    // ===== CHAT =====
    const chat = await ProjectChat.find({ projectId: project._id })
      .sort({ createdAt: 1 })
      .limit(50);

    res.json({
      project: {
        title: project.title,
        description: project.description,
        status: project.status,
        startDate: project.createdAt,
        deadline: project.projectDeadline,
        lastUpdated: project.updatedAt,
      },
      stats,
      tasks: tasks.map(t => ({
        title: t.title,
        status: t.status,
        deadline: t.deadline,
        lastUpdate: t.updatedAt,
        assigneeId: t.assignedTo,
      })),
      members,
      chat,
    });

  } catch (err) {
    console.error("DASHBOARD ERROR:", err);
    res.status(500).json({ message: "Dashboard load failed" });
  }
});


// ================= PROJECT CHAT APIs =================

// GET CHAT MESSAGES
app.get("/api/projects/:projectId/chat", auth, async (req, res) => {
  const { projectId } = req.params;
  const project = await Project.findById(projectId);
if (!project) {
  return res.status(404).json({ message: "Project not found" });
}

const role = getUserRoleInProject(project, req.user.id);
if (!role) {
  return res.status(403).json({ message: "Not a project member" });
}

  if (!mongoose.Types.ObjectId.isValid(projectId)) {
    return res.status(400).json({ message: "Invalid project ID" });
  }

  const chat = await ProjectChat.find({ projectId })
    .sort({ createdAt: 1 });

  res.json(chat);
});

// SEND CHAT MESSAGE
app.post("/api/projects/:projectId/chat", auth, async (req, res) => {
  const { projectId } = req.params;
  const { message } = req.body;

  if (!message || !message.trim()) {
    return res.status(400).json({ message: "Message is required" });
  }

  const project = await Project.findById(projectId);
  if (!project) {
    return res.status(404).json({ message: "Project not found" });
  }

  const role = getUserRoleInProject(project, req.user.id);
  if (!role) {
    return res.status(403).json({ message: "Not a project member" });
  }

  const user = await User.findById(req.user.id);

  const chat = await ProjectChat.create({
    projectId,
    senderId: user._id,
    senderName: user.name,
    message,
  });

  res.json(chat);
});

/* ================= MEMBER UPLOAD (UPDATED & FIXED) ================= */
app.post(
  "/api/projects/:projectId/member/uploads",
  auth,
  upload.single("file"),
  async (req, res) => {
    try {
      const { projectId } = req.params;
      const userId = req.user.id;
      const { taskId } = req.body;

      // ❌ No file
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      // ❌ No taskId (CRITICAL)
      if (!taskId) {
        return res.status(400).json({ message: "Task ID is required" });
      }

      // ✅ Save upload
      await MemberUpload.create({
        projectId: new mongoose.Types.ObjectId(projectId),
        memberId: new mongoose.Types.ObjectId(userId),
        fileName: req.file.originalname,
        filePath: req.file.path,
      });

      // ✅ Find EXACT task (not random)
      const task = await Task.findOne({
        _id: taskId,
        projectId,
        assignedTo: userId,
      });

      if (!task) {
        return res.status(404).json({ message: "Task not found for member" });
      }

      // ✅ MARK TASK DONE (THIS IS THE PART YOU ASKED)
      task.status = "done";
      await task.save();

      res.json({
        message: "Upload successful and task marked as done",
      });
    } catch (err) {
      console.error("UPLOAD ERROR:", err);
      res.status(500).json({ message: "Upload failed" });
    }
  }
);




// ================= PROJECT MEMBERS (MANAGER / OWNER) =================
app.get("/api/projects/:id/members", auth, async (req, res) => {
  const project = await Project.findById(req.params.id);
  if (!project)
    return res.status(404).json({ message: "Project not found" });

  const members = [];

  // owner
  const owner = await User.findById(project.owner.userId);
  if (owner) {
    members.push({
      id: owner._id,
      name: owner.name,
      email: owner.email,
      role: "OWNER",
      progressPercent: 100,
    });
  }

  // manager
  const manager = await User.findById(project.manager.userId);
  if (manager) {
    members.push({
      id: manager._id,
      name: manager.name,
      email: manager.email,
      role: "MANAGER",
      progressPercent: 100,
    });
  }

  // team members
  for (const m of project.team.filter((t) => t.status === "accepted")) {
    const user = await User.findById(m.userId);
    if (!user) continue;

    const tasks = await Task.find({
      projectId: project._id,
      assignedTo: user._id,
    });

    const done = tasks.filter((t) => t.status === "done").length;
    const progress = tasks.length
      ? Math.round((done / tasks.length) * 100)
      : 0;

    members.push({
      id: user._id,
      name: user.name,
      email: user.email,
      role: m.role,
      progressPercent: progress,
      totalTasks: tasks.length,
      doneTasks: done,
      overdueTasks: tasks.filter(
        (t) => t.deadline && t.deadline < new Date() && t.status !== "done"
      ).length,
    });
  }

  res.json(members);
});

// ================= MEMBER DETAIL (MANAGER / OWNER ONLY) =================
app.get(
  "/api/projects/:projectId/members/:memberId/detail",
  auth,
  async (req, res) => {
    const { projectId, memberId } = req.params;

    const project = await Project.findById(projectId);

    const isOwner =
      project.owner.userId.toString() === req.user.id;
    const isManager =
      project.manager.userId.toString() === req.user.id;

    if (!isOwner && !isManager) {
      return res
        .status(403)
        .json({ message: "Only owner or manager allowed" });
    }

    const uploads = await MemberUpload.find({
      projectId,
      memberId,
    }).sort({ createdAt: -1 });

    const tasks = await Task.find({
      projectId,
      assignedTo: memberId,
    });

    res.json({
      uploads: uploads.map((u) => ({
        fileName: u.fileName,
        uploadedAt: u.createdAt,
        url: `http://localhost:5000/uploads/${path.basename(
          u.filePath
        )}`,
      })),
      tasks: tasks.map((t) => ({
        title: t.title,
        status: t.status,
        lastUpdate: t.updatedAt,
      })),
    });
  }
);

app.get("/api/profile", auth, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.user.id);

    // ✅ USER
    const user = await User.findById(userId).lean();
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // ✅ PROJECTS (OWNER / MANAGER / TEAM)
    const projects = await Project.find({
      $or: [
        { "owner.userId": userId },
        { "manager.userId": userId },
        { "team.userId": userId }
      ],
    }).lean();

    // ✅ TASKS (FIXED QUERY)
    const tasks = await Task.find({
      assignedTo: userId
    })
      .sort({ updatedAt: -1 })
      .lean();

    // ✅ TASK STATS
    const tasksCompleted = tasks.filter(
      (task) => task.status === "done"
    ).length;

    const totalTasks = tasks.length;
    const hoursLogged = tasksCompleted * 2;

    // ✅ ROLE DETECTION
    let role = "Team Member";

    if (
      projects.some(
        (p) => p.owner?.userId?.toString() === userId.toString()
      )
    ) {
      role = "Owner";
    } else if (
      projects.some(
        (p) => p.manager?.userId?.toString() === userId.toString()
      )
    ) {
      role = "Manager";
    }

    // ✅ RECENT ACTIVITY
    const recentActivity = tasks.slice(0, 5).map((task) => ({
      label: `Task "${task.title}" marked as ${task.status}`,
      time: new Date(task.updatedAt || task.createdAt).toLocaleDateString(),
      meta: "Task update",
    }));

    // ✅ RESPONSE
    res.json({
      name: user.name,
      email: user.email,
      phone: user.phone || "",
      role,
      memberSince: new Date(user.createdAt).toDateString(),
      tasksCompleted,
      totalTasks,
      hoursLogged,
      recentActivity,
    });

  } catch (error) {
    console.error("PROFILE ERROR:", error);
    res.status(500).json({ message: "Profile load failed" });
  }
});

// ================= DASHBOARD =================
app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.user.id);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const projects = await Project.find({
      $or: [
        { "owner.userId": userId },
        { "manager.userId": userId },
        { "team.userId": userId },
      ],
    }).lean();

    const tasks = await Task.find({ assignedTo: userId }).lean();

    const activeProjects = projects.filter(
      (p) => p.status === "active"
    ).length;

    const upcomingDeadlines = tasks.filter(
      (t) =>
        t.deadline &&
        new Date(t.deadline) >= new Date() &&
        t.status !== "done"
    ).length;

    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    res.json({
      user: {
        name: user.name,
        email: user.email,
      },
      summary: {
        activeProjects,
        myTasks: tasks.length,
        upcomingDeadlines,
      },
      projects: projects.map((p) => ({
        id: p._id,
        title: p.title,
        role:
          p.owner?.userId?.toString() === userId.toString()
            ? "OWNER"
            : p.manager?.userId?.toString() === userId.toString()
            ? "MANAGER"
            : "MEMBER",
        status: p.status,
      })),
      notifications,
    });
  } catch (err) {
    console.error("DASHBOARD ERROR:", err);
    res.status(500).json({ message: "Dashboard load failed" });
  }
});
// ✅ STATIC ROUTES FIRST
// ✅ MUST BE BEFORE /api/projects/:id
// ================= DASHBOARD SLIDER APIs =================

// ✅ MUST BE BEFORE ANY /api/projects/:id
app.get("/api/projects/active-projects", auth, async (req, res) => {
  console.log("🔥 ACTIVE PROJECTS API HIT");

  try {
    const userId = new mongoose.Types.ObjectId(req.user.id);

    const projects = await Project.find({
      status: "active",
      $or: [
        { "owner.userId": userId },
        { "manager.userId": userId },
        { "team.userId": userId },
      ],
    }).lean();

    res.json(
      projects.map(p => ({
        id: p._id,
        title: p.title,
        role:
          p.owner?.userId?.toString() === userId.toString()
            ? "OWNER"
            : p.manager?.userId?.toString() === userId.toString()
            ? "MANAGER"
            : "MEMBER",
      }))
    );
  } catch (err) {
    console.error("ACTIVE PROJECTS ERROR:", err);
    res.status(500).json({ message: "Active projects failed" });
  }
});
/**
 * UPCOMING DEADLINES
 */
app.get("/api/deadlines/upcoming", auth, async (req, res) => {
  const tasks = await Task.find({
    assignedTo: req.user.id,
    deadline: { $gte: new Date() },
    status: { $ne: "done" },
  }).lean();

  res.json(
    tasks.map((t) => ({
      id: t._id,
      title: t.title,
      dueDate: t.deadline,
    }))
  );
});

// ================= DAILY TASK UPDATE (MEMBER) =================
app.post("/api/tasks/:taskId/daily-update", auth, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status, note } = req.body;
    const userId = req.user.id;

    if (!note) {
      return res.status(400).json({ message: "Note is required" });
    }

    const task = await Task.findById(taskId);
    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // 🔐 Only assigned member can update
    if (task.assignedTo?.toString() !== userId.toString()) {
      return res.status(403).json({ message: "Not your task" });
    }

    // ✅ Push daily update
    task.dailyUpdates.push({
      status,
      note,
      updatedBy: userId,
    });

    // ✅ Sync main task status
    task.status = status === "done" ? "done" : "in-progress";

    await task.save();

    res.json({ message: "Daily update saved" });
  } catch (err) {
    console.error("DAILY UPDATE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ======================================================
   DYNAMIC ROUTES (ALWAYS AFTER STATIC ROUTES)
====================================================== */

/**
 * PROJECT BY ID
 */
/* ================= PROJECT BY ID (ALWAYS LAST) ================= */


app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const projects = await Project.find({
      $or: [
        { "owner.userId": userId },
        { "manager.userId": userId },
        { "team.userId": userId },
      ],
    });

    const tasks = await Task.find({ assignedTo: userId });

    const activeProjects = projects.filter(
      (p) => p.status === "active"
    ).length;

    const upcomingDeadlines = tasks.filter(
      (t) => t.deadline && t.status !== "done"
    ).length;

    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .limit(20);

    res.json({
      user: {
        name: user.name,
        email: user.email,
      },
      summary: {
        activeProjects,
        myTasks: tasks.length,
        upcomingDeadlines,
      },
      notifications,
    });
  } catch (err) {
    console.error("DASHBOARD API ERROR:", err);
    res.status(500).json({ message: "Dashboard load failed" });
  }
});
/* ================= FINAL PROJECT REVIEW ================= */
app.get("/api/projects/:id/final-review", auth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }

    const project = await Project.findById(id);
    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    // ✅ FIX: allow ANY project member (OWNER / MANAGER / TEAM)
    const role = getUserRoleInProject(project, userId);
    if (!role) {
      return res.status(403).json({ message: "Access denied" });
    }

    const tasks = await Task.find({ projectId: project._id });

    const total = tasks.length;
    const completed = tasks.filter(t => t.status === "done").length;
    const inProgress = tasks.filter(t => t.status === "in-progress").length;
    const blocked = tasks.filter(
      t => t.deadline && t.deadline < new Date() && t.status !== "done"
    ).length;

    const members = [];

    // OWNER
    const owner = await User.findById(project.owner.userId);
    if (owner) {
      members.push({
        name: owner.name,
        role: "OWNER",
        done: 0,
        total: 0,
        uploads: 0,
      });
    }

    // MANAGER
    const manager = await User.findById(project.manager.userId);
    if (manager) {
      members.push({
        name: manager.name,
        role: "MANAGER",
        done: 0,
        total: 0,
        uploads: 0,
      });
    }

    // TEAM MEMBERS
    for (const m of project.team.filter(t => t.status === "accepted")) {
      const user = await User.findById(m.userId);
      if (!user) continue;

      const userTasks = tasks.filter(
        t => t.assignedTo?.toString() === user._id.toString()
      );

      const uploads = await MemberUpload.countDocuments({
        projectId: project._id,
        memberId: user._id,
      });

      members.push({
        name: user.name,
        role: m.role,
        done: userTasks.filter(t => t.status === "done").length,
        total: userTasks.length,
        uploads,
      });
    }

    res.json({
      project: { title: project.title },
      tasks: {
        total,
        completed,
        inProgress,
        blocked,
      },
      members,
    });

  } catch (err) {
    console.error("FINAL REVIEW ERROR:", err);
    res.status(500).json({ message: "Final review failed" });
  }
});

/* ================= SERVER ================= */

// ✅ SERVE FRONTEND FILES
const FRONTEND_PATH = path.join(__dirname, "..", "frontend");
app.use(express.static(FRONTEND_PATH));

// ✅ Root route (fixes "Cannot GET /")
app.get("/", (req, res) => {
  res.sendFile(path.join(FRONTEND_PATH, "login.html"));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log("🚀 Server running on http://localhost:" + PORT)
);