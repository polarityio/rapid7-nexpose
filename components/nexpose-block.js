let tagId = 2; // high is the first tag in the list, so we let it default

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),

  tagsLink: Ember.computed('block.data.details', function() {
    return this.get('block.data.details')
      .links.filter(function(link) {
        return link.rel === 'Tags';
      })
      .pop();
  }),
  actions: {
    applyTag: function(assetId) {
      let self = this;
      let tagsLink = self.get('tagsLink');
      this.set('isUpdatingCriticality', true);

      this.sendIntegrationMessage({
        type: 'applyTag',
        assetId: assetId,
        tagId: tagId,
        tagsLink: tagsLink.href
      })
        .then((tags) => {
          console.log('tag successfully added', tags);
          self.set('block.data.details.appliedTags', tags);
          self.notifyPropertyChange('block.data.details');
        })
        .catch((err) => {
          console.error('error applying tag', err);
          this.set('updateError', JSON.stringify(err, null, 4));
          // TODO display error message
        })
        .finally(() => {
          this.set('isUpdatingCriticality', false);
        });
    },
    onSelectTag: function(value) {
      tagId = value;
    }
  }
});
