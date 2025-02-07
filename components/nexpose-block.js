let tagId = 2; // high is the first tag in the list, so we let it default

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  resources: Ember.computed.alias('details.resources'),
  state: Ember.computed.alias('block._state'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  tagsLink: Ember.computed('block.data.details', function () {
    return this.get('block.data.details')
      .links.filter(function (link) {
        return link.rel === 'Tags';
      })
      .pop();
  }),
  init() {
    this._super(...arguments);
    if (!this.get('block._state')) {
      this.set('block._state', []);
      for (let i = 0; i < this.get('resources.length'); i++) {
        this.set(`state.${i}`, {});
      }
    }
    this.set('state.0.__show', true);
    console.info(this.get('state'));
  },
  actions: {
    changeTab: function (tabName, assetIndex) {
      console.info('changing tab to', tabName);
      this.set(`state.${assetIndex}.__activeTab`, tabName);
    },
    applyTag: function (assetId) {
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
    onSelectTag: function (value) {
      tagId = value;
    }
  }
});
