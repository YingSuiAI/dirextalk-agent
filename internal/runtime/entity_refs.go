package runtime

func collectRelatedEntityIDs(steps []Step) ([]string, []string, error) {
	var taskValues, planValues []string
	for _, step := range steps {
		if step.Kind != StepToolResult || step.ToolResult.IsError {
			continue
		}
		taskValues = append(taskValues, step.ToolResult.RelatedTaskIDs...)
		planValues = append(planValues, step.ToolResult.RelatedPlanIDs...)
	}
	taskIDs, err := normalizeRelatedEntityIDs(taskValues)
	if err != nil {
		return nil, nil, err
	}
	planIDs, err := normalizeRelatedEntityIDs(planValues)
	if err != nil {
		return nil, nil, err
	}
	return taskIDs, planIDs, nil
}
