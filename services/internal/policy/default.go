// The default policy for the digital substation scenario.

package policy

import "github.com/philipfleischer/zero-trust-continuum/services/internal/model"

// DefaultSubstationPolicy returns the baseline policy for the digital
// substation. It encodes the IEC 62443 zones and the Purdue levels as ABAC
// rules, with least privilege for every kind of subject:
//
//  1. anything from a subject with trust below 0.3 is denied
//  2. an auditor may never do anything but read (separation of duties)
//  3. edge devices (PMUs, meters, IEDs) may write telemetry to their own zone only
//  4. fog services may read telemetry of their own zone
//  5. operating a breaker needs role operator, trust >= 0.8 and a source in
//     the control zones; it is logged and re-verified every 10 s
//  6. in emergency (break-glass) mode an operator may operate a breaker with
//     trust >= 0.5, always logged and alerted
//  7. setpoint changes need role engineer and trust >= 0.7
//  8. an auditor may read telemetry, aggregates, policies and the audit log
//  9. cloud analytics may read aggregated telemetry of all zones
//  10. tasks may be offloaded to fog and cloud nodes, and to edge devices in
//     their own zone, with trust >= 0.5
//  11. services may be migrated by fog and cloud nodes with trust >= 0.7
//  12. policy administration is only for spiffe://*/cloud/admin/* with trust >= 0.8
//
// It returns a new value on every call, so callers may modify it. The same
// rules exist as JSON in deploy/policies/substation.json.
func DefaultSubstationPolicy() *Policy {
	condition := func(attribute, operator, value string) Condition {
		return Condition{Attribute: attribute, Operator: operator, Value: value}
	}
	return &Policy{
		Version:     1,
		Description: "digital substation baseline (IEC 62443 zones, Purdue levels, least privilege)",
		Rules: []Rule{
			{ID: "deny-untrusted", Effect: model.Deny, Description: "zero trust floor",
				Conditions: []Condition{condition("context.trustScore", "lt", "0.3")}, TTLSeconds: 5},
			{ID: "auditor-read-only", Effect: model.Deny, Description: "auditors observe, they never act",
				Subjects: []string{"role:auditor"}, Conditions: []Condition{condition("action", "neq", "read")}, TTLSeconds: 60},
			{ID: "edge-write-telemetry", Effect: model.Allow, Description: "sensors report to their own zone",
				Actions: []string{"write"}, Resources: []string{"type:telemetry"},
				Conditions:  []Condition{condition("subject.layer", "eq", "edge"), condition("subject.zone", "sameAs", "resource.zone")},
				Obligations: []string{"rate-limit:50/s"}, TTLSeconds: 60},
			{ID: "fog-read-telemetry", Effect: model.Allow, Description: "fog services process their own zone",
				Actions: []string{"read"}, Resources: []string{"type:telemetry"},
				Conditions: []Condition{condition("subject.layer", "eq", "fog"), condition("subject.zone", "sameAs", "resource.zone"),
					condition("context.trustScore", "gte", "0.5")}, TTLSeconds: 60},
			{ID: "operate-breaker", Effect: model.Allow, Description: "switching needs high trust from a control zone",
				Subjects: []string{"role:operator"}, Actions: []string{"operate"}, Resources: []string{"type:breaker"},
				Conditions: []Condition{condition("context.trustScore", "gte", "0.8"),
					condition("context.sourceZone", "in", "control-centre,substation-hmi")},
				Obligations: []string{"log", "reverify:10s"}, TTLSeconds: 10},
			{ID: "break-glass-breaker", Effect: model.Allow, Description: "emergency switching, always alerted",
				Subjects: []string{"role:operator"}, Actions: []string{"operate"}, Resources: []string{"type:breaker"},
				Conditions:  []Condition{condition("context.emergency", "eq", "true"), condition("context.trustScore", "gte", "0.5")},
				Obligations: []string{"log", "alert:soc"}, TTLSeconds: 1},
			{ID: "write-setpoint", Effect: model.Allow, Description: "engineers tune protection settings",
				Subjects: []string{"role:engineer"}, Actions: []string{"write"}, Resources: []string{"type:setpoint"},
				Conditions: []Condition{condition("context.trustScore", "gte", "0.7")}, Obligations: []string{"log"}, TTLSeconds: 10},
			{ID: "auditor-read", Effect: model.Allow, Description: "auditors read across zones",
				Subjects: []string{"role:auditor"}, Actions: []string{"read"},
				Resources:  []string{"type:telemetry", "type:telemetry-aggregate", "type:policy", "type:audit-log"},
				Conditions: []Condition{condition("context.trustScore", "gte", "0.5")}, Obligations: []string{"log"}, TTLSeconds: 60},
			{ID: "cloud-read-aggregates", Effect: model.Allow, Description: "analytics sees aggregates, not raw data",
				Actions: []string{"read"}, Resources: []string{"type:telemetry-aggregate"},
				Conditions: []Condition{condition("subject.layer", "eq", "cloud"), condition("context.trustScore", "gte", "0.5")}, TTLSeconds: 60},
			{ID: "execute-task", Effect: model.Allow, Description: "offloading to fog and cloud",
				Actions: []string{"execute"}, Resources: []string{"type:task"},
				Conditions: []Condition{condition("subject.layer", "in", "fog,cloud"), condition("context.trustScore", "gte", "0.5")}, TTLSeconds: 30},
			{ID: "edge-offload-task", Effect: model.Allow, Description: "edge devices run tasks in their own zone",
				Actions: []string{"execute"}, Resources: []string{"type:task"},
				Conditions: []Condition{condition("subject.layer", "eq", "edge"), condition("subject.zone", "sameAs", "resource.zone"),
					condition("context.trustScore", "gte", "0.5")}, TTLSeconds: 30},
			{ID: "migrate-service", Effect: model.Allow, Description: "moving services between nodes",
				Actions: []string{"migrate"}, Resources: []string{"type:service"},
				Conditions: []Condition{condition("subject.layer", "in", "fog,cloud"), condition("context.trustScore", "gte", "0.7")}, TTLSeconds: 10},
			{ID: "policy-admin", Effect: model.Allow, Description: "only cloud admins change the policy",
				Subjects: []string{"spiffe://*/cloud/admin/*"}, Actions: []string{"admin", "read", "write"},
				Resources: []string{"type:policy"}, Conditions: []Condition{condition("context.trustScore", "gte", "0.8")},
				Obligations: []string{"log"}, TTLSeconds: 5},
		},
	}
}
