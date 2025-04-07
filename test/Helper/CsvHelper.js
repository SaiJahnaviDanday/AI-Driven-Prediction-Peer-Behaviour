// csvHelper.js
const fs = require("fs");
const path = require("path");
const createCsvWriter = require("csv-writer").createObjectCsvWriter;

// CSV File Path
const csvFilePath = path.join(__dirname, "transaction_logs.csv");

// Helper Functions

// Ensure CSV log file exists and create it if not
function ensureLogFileExists() {
  const fileExists = fs.existsSync(csvFilePath);
  if (!fileExists) {
    fs.writeFileSync(
      csvFilePath,
      "Timestamp,Member Address,Name,Type,Role,Initial Status,Initial Last Status Update,Action,Final Status,Final Last Status Update,Gas Used,Penalty,Delay,Is Status Changed,Latency,Blocking End Time,Reward,Token Balance\n"
    );
  }
}

// Create a CSV Writer instance
const csvWriter = createCsvWriter({
  path: csvFilePath,
  header: [
    { id: "timestamp", title: "Timestamp" },
    { id: "member", title: "Member Address" },
    { id: "name", title: "Name" },
    { id: "type", title: "Type" },
    { id: "role", title: "Role" },
    { id: "initialStatus", title: "Initial Status" },
    { id: "initialLastStatusUpdate", title: "Initial Last Status Update" },
    { id: "action", title: "Action" },
    { id: "finalStatus", title: "Final Status" },
    { id: "finalLastStatusUpdate", title: "Final Last Status Update" },
    { id: "gasUsed", title: "Gas Used" },
    { id: "penalty", title: "Penalty" },
    { id: "delay", title: "Delay" },
    { id: "isStatusChanged", title: "Is Status Changed" },
    { id: "latency", title: "Latency" },
    { id: "blockingEndTime", title: "Blocking End Time" },
    { id: "reward", title: "Reward" },
    { id: "tokenBalance", title: "Token Balance" },
  ],
  append: true, // Ensures logs are appended to the CSV file
});

// Write data to CSV
async function writeLogToCSV(
  initialStatus,
  finalStatus,
  action,
  totalGasUsed,
  penalty,
  measurments
) {
  await csvWriter.writeRecords([
    {
      timestamp: initialStatus.timestamp,
      member: initialStatus.member,
      name: initialStatus.name,
      type: initialStatus.type,
      role: initialStatus.role,
      initialStatus: initialStatus.status,
      initialLastStatusUpdate: initialStatus.lastStatusUpdate,
      action: action,
      finalStatus: finalStatus.status,
      finalLastStatusUpdate: finalStatus.lastStatusUpdate,
      gasUsed: totalGasUsed,
      penalty: penalty,
      delay: measurments.delay,
      isStatusChanged: measurments.isStatusChanged,
      latency: measurments.latency,
      blockingEndTime: measurments.blockingEndTime,
      tokenBalance: measurments.tokenBalance,
      reward: measurments.reward,
    },
  ]);

  console.log(
    `Logged initial and final data to CSV for: ${initialStatus.member}`
  );
}

// Export the functions to be used in other files
module.exports = {
  ensureLogFileExists,
  writeLogToCSV,
};
